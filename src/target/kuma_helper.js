const crypto = require("node:crypto");
const { io } = require("socket.io-client");

const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function requestJson(baseUrl, path, options = {}) {
    const response = await fetch(baseUrl + path, {
        ...options,
        headers: { "content-type": "application/json", ...(options.headers || {}) },
    });
    let body = null;
    try {
        body = await response.json();
    } catch (_) {
        body = null;
    }
    if (!response.ok) {
        throw new Error(`Kuma HTTP ${response.status} at ${path}`);
    }
    return body;
}

function emit(socket, event, ...args) {
    return new Promise((resolve) => socket.emit(event, ...args, resolve));
}

function emitMutation(socket, readOnly, event, ...args) {
    if (readOnly) throw new Error(`Kuma plan mode attempted forbidden write event ${event}`);
    return emit(socket, event, ...args);
}

function connect(socket) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("Kuma Socket.IO connection timed out")), 15000);
        socket.once("connect", () => {
            clearTimeout(timer);
            resolve();
        });
        socket.once("connect_error", (error) => {
            clearTimeout(timer);
            reject(new Error(`Kuma Socket.IO connection failed: ${error.message}`));
        });
    });
}

async function connectWithRetry(baseUrl) {
    let lastError = new Error("Kuma Socket.IO connection failed");
    for (let attempt = 0; attempt < 30; attempt += 1) {
        const socket = io(baseUrl, { timeout: 10000, reconnection: false });
        try {
            await connect(socket);
            return socket;
        } catch (error) {
            lastError = error;
            socket.close();
            await wait(1000);
        }
    }
    throw lastError;
}

async function ensureDatabase(baseUrl) {
    for (let attempt = 0; attempt < 30; attempt += 1) {
        try {
            const info = await requestJson(baseUrl, "/setup-database-info");
            if (info && info.needSetup) {
                await requestJson(baseUrl, "/setup-database", {
                    method: "POST",
                    body: JSON.stringify({ dbConfig: { type: "sqlite" } }),
                });
            }
            return;
        } catch (error) {
            if (attempt === 29) throw error;
            await wait(1000);
        }
    }
}

function parseJsonField(value, fallback) {
    if (typeof value !== "string") return value ?? fallback;
    try {
        return JSON.parse(value);
    } catch (_) {
        return fallback;
    }
}

function normalizeMonitorPayload(monitor) {
    monitor.accepted_statuscodes = parseJsonField(monitor.accepted_statuscodes, ["200-299"]);
    monitor.conditions = parseJsonField(monitor.conditions, []);
    monitor.rabbitmqNodes = parseJsonField(monitor.rabbitmqNodes, []);
    monitor.kafkaProducerBrokers = parseJsonField(monitor.kafkaProducerBrokers, []);
    monitor.kafkaProducerSaslOptions = parseJsonField(monitor.kafkaProducerSaslOptions, {
        mechanism: "None",
    });
    monitor.notificationIDList = monitor.notificationIDList || {};
    return monitor;
}

function configHash(monitor, key) {
    const keyHash = crypto.createHash("sha256").update(key).digest("hex");
    const stable = {
        id: String(monitor.id),
        name: monitor.name,
        url: monitor.url,
        type: "keyword",
        method: "GET",
        keyword: '"success":true',
        key_hash: keyHash,
        interval: monitor.interval,
        timeout: monitor.timeout,
        retries: monitor.maxretries,
        active: monitor.active !== false,
    };
    return crypto.createHash("sha256").update(JSON.stringify(stable)).digest("hex");
}

function desiredMonitor(source, existing, input, parentID) {
    const url = `${input.source_base_url.replace(/\/$/, "")}/api/onboard/status/monitors/${encodeURIComponent(String(source.id))}`;
    const marker = `meowai-deploy:${input.deployment_id}:source-monitor:${source.id}`;
    const monitor = existing ? { ...existing } : {
        name: source.name,
        description: marker,
        parent: parentID,
        type: "keyword",
        subtype: null,
        url,
        method: "GET",
        body: null,
        headers: "{}",
        interval: 60,
        retryInterval: 60,
        timeout: 48,
        maxretries: 0,
        maxredirects: 10,
        accepted_statuscodes: ["200-299"],
        notificationIDList: {},
        conditions: [],
        rabbitmqNodes: [],
        kafkaProducerBrokers: [],
        active: true,
        weight: 1000,
        saveResponse: false,
        saveErrorResponse: true,
        responseMaxLength: 1024,
        expiryNotification: false,
        domainExpiryNotification: false,
        ignoreTls: false,
        upsideDown: false,
        invertKeyword: false,
        cacheBust: false,
        retryOnlyOnStatusCodeFailure: false,
    };
    monitor.name = source.name;
    monitor.description = marker;
    monitor.type = "keyword";
    monitor.parent = parentID;
    monitor.url = url;
    monitor.method = "GET";
    monitor.headers = JSON.stringify({ Authorization: `Bearer ${input.status_key}` });
    monitor.keyword = '"success":true';
    monitor.invertKeyword = false;
    monitor.interval = Number(source.interval) > 0 ? Number(source.interval) : 60;
    monitor.retryInterval = monitor.interval;
    monitor.timeout = Number(source.timeout) > 0 ? Number(source.timeout) : 48;
    monitor.maxretries = Number(source.retries) >= 0 ? Number(source.retries) : 0;
    monitor.accepted_statuscodes = ["200-299"];
    monitor.notificationIDList = {};
    monitor.active = source.display_enabled !== false;
    monitor.weight = (Number(source.sort_order) + 1) * 1000;
    monitor.id = existing ? existing.id : undefined;
    return { monitor: normalizeMonitorPayload(monitor), marker, url };
}

function monitorDrifted(existing, desired) {
    if (!existing) return false;
    return existing.name !== desired.name
        || existing.url !== desired.url
        || existing.type !== "keyword"
        || Number(existing.parent || 0) !== Number(desired.parent || 0)
        || existing.keyword !== '"success":true'
        || existing.headers !== desired.headers
        || Number(existing.interval) !== Number(desired.interval)
        || Number(existing.timeout) !== Number(desired.timeout)
        || Number(existing.maxretries) !== Number(desired.maxretries)
        || JSON.stringify(existing.accepted_statuscodes || []) !== JSON.stringify(["200-299"])
        || Boolean(existing.active) !== Boolean(desired.active);
}

function managedSnapshot(input, pageResult, monitorList) {
    const groupIDByMonitorID = new Map();
    const groups = [];
    for (const monitor of Object.values(monitorList || {})) {
        const marker = String(monitor.description || "");
        const prefix = `meowai-deploy:${input.deployment_id}:source-group:`;
        if (!marker.startsWith(prefix)) continue;
        const sourceGroupID = marker.slice(prefix.length);
        groupIDByMonitorID.set(Number(monitor.id), sourceGroupID);
        groups.push({
            source_group_id: sourceGroupID,
            name: String(monitor.name || ""),
            active: monitor.active !== false,
        });
    }
    groups.sort((left, right) => left.source_group_id.localeCompare(right.source_group_id));

    const monitors = [];
    for (const monitor of Object.values(monitorList || {})) {
        const marker = String(monitor.description || "");
        const prefix = `meowai-deploy:${input.deployment_id}:source-monitor:`;
        if (!marker.startsWith(prefix)) continue;
        const headers = parseJsonField(monitor.headers, {});
        const authorization = String(headers.Authorization || headers.authorization || "");
        monitors.push({
            source_monitor_id: marker.slice(prefix.length),
            name: String(monitor.name || ""),
            group_id: groupIDByMonitorID.get(Number(monitor.parent || 0)) || "",
            url: String(monitor.url || ""),
            key_sha256: crypto.createHash("sha256").update(authorization).digest("hex"),
            interval: Number(monitor.interval || 0),
            timeout: Number(monitor.timeout || 0),
            retries: Number(monitor.maxretries || 0),
            enabled: monitor.active !== false,
        });
    }
    monitors.sort((left, right) => left.source_monitor_id.localeCompare(right.source_monitor_id));

    const pageExists = Boolean(pageResult && pageResult.ok);
    const page = pageExists ? (pageResult.config || {}) : {};
    return {
        page: {
            exists: pageExists,
            slug: input.status_page_slug,
            title: pageExists ? String(page.title || "") : "",
            description: pageExists ? String(page.description || "") : "",
            theme: pageExists ? String(page.theme || "auto") : "auto",
        },
        groups,
        monitors,
    };
}

async function sync(input) {
    const baseUrl = "http://127.0.0.1:3001";
    const readOnly = input.mode === "plan";
    if (readOnly) {
        const database = await requestJson(baseUrl, "/setup-database-info");
        if (database && database.needSetup) {
            throw new Error("Kuma is not initialized; run onboard before sync");
        }
    } else {
        await ensureDatabase(baseUrl);
    }
    const socket = await connectWithRetry(baseUrl);
    try {
        let setup = await emit(socket, "needSetup");
        if (setup) {
            if (readOnly) throw new Error("Kuma account is not initialized; run onboard before sync");
            const setupResult = await emitMutation(socket, readOnly, "setup", input.kuma_username, input.kuma_password);
            if (!setupResult || !setupResult.ok) throw new Error(setupResult?.msg || "Kuma setup failed");
        }
        const login = await emit(socket, "login", {
            username: input.kuma_username,
            password: input.kuma_password,
        });
        if (!login || !login.ok) {
            throw new Error(login?.tokenRequired ? "Kuma account requires 2FA" : (login?.msg || "Kuma login failed"));
        }

        const pageResult = await emit(socket, "getStatusPage", input.status_page_slug);
        let pageConfig;
        if (pageResult && pageResult.ok) {
            pageConfig = pageResult.config;
        } else if (!readOnly) {
            const added = await emitMutation(socket, readOnly, "addStatusPage", input.website_name, input.status_page_slug);
            if (!added || !added.ok) throw new Error(added?.msg || "Kuma status page creation failed");
            const created = await emit(socket, "getStatusPage", input.status_page_slug);
            if (!created || !created.ok) throw new Error(created?.msg || "Kuma status page readback failed");
            pageConfig = created.config;
        } else {
            pageConfig = {};
        }
        if (!readOnly && pageResult && pageResult.ok && !input.force) {
            const current = pageResult.config || {};
            if (String(current.title || "") !== input.website_name
                || String(current.description || "") !== String(input.manifest.page_description || "")
                || String(current.theme || "auto") !== String(input.manifest.theme || "auto")) {
                throw new Error("managed Kuma status page drifted; rerun sync with --force");
            }
        }

        const monitorListPromise = new Promise((resolve) => socket.once("monitorList", resolve));
        const monitorListAck = await emit(socket, "getMonitorList");
        if (!monitorListAck || !monitorListAck.ok) throw new Error(monitorListAck?.msg || "Kuma monitor list failed");
        const monitorList = await monitorListPromise;
        const existingByMarker = new Map();
        const existingGroupByMarker = new Map();
        for (const monitor of Object.values(monitorList || {})) {
            const marker = String(monitor.description || "");
            if (marker.startsWith(`meowai-deploy:${input.deployment_id}:source-monitor:`)) {
                if (existingByMarker.has(marker)) throw new Error(`duplicate managed Kuma monitor marker: ${marker}`);
                existingByMarker.set(marker, monitor);
            } else if (marker.startsWith(`meowai-deploy:${input.deployment_id}:source-group:`)) {
                if (existingGroupByMarker.has(marker)) throw new Error(`duplicate managed Kuma group marker: ${marker}`);
                existingGroupByMarker.set(marker, monitor);
            }
        }
        if (!readOnly && !input.force) {
            for (const source of input.manifest.monitors || []) {
                const groupKey = String(source.group_id || source.group || "default");
                const groupMarker = `meowai-deploy:${input.deployment_id}:source-group:${groupKey}`;
                const existingGroup = existingGroupByMarker.get(groupMarker);
                if (existingGroup && String(existingGroup.name || "") !== String(source.group || groupKey)) {
                    throw new Error(`managed Kuma group ${groupKey} drifted; rerun sync with --force`);
                }
                const marker = `meowai-deploy:${input.deployment_id}:source-monitor:${source.id}`;
                const existing = existingByMarker.get(marker);
                if (!existing) continue;
                const desired = desiredMonitor(
                    source,
                    existing,
                    input,
                    existingGroup ? Number(existingGroup.id) : null,
                );
                if (monitorDrifted(existing, desired.monitor)) {
                    throw new Error(`managed Kuma monitor ${existing.id} drifted; rerun sync with --force`);
                }
            }
        }
        if (readOnly) {
            return {
                ok: true,
                page_slug: input.status_page_slug,
                snapshot: managedSnapshot(input, pageResult, monitorList),
                monitors: [],
            };
        }
        const groups = [];
        const groupsByID = new Map();
        const groupMonitorByID = new Map();
        for (const source of input.manifest.monitors || []) {
            const groupKey = String(source.group_id || source.group || "default");
            if (groupsByID.has(groupKey)) continue;
            const groupName = source.group || groupKey;
            const marker = `meowai-deploy:${input.deployment_id}:source-group:${groupKey}`;
            const existing = existingGroupByMarker.get(marker);
            const groupMonitor = existing ? { ...existing } : {
                name: groupName,
                description: marker,
                parent: null,
                type: "group",
                interval: 60,
                retryInterval: 60,
                timeout: 48,
                maxretries: 0,
                accepted_statuscodes: ["200-299"],
                notificationIDList: {},
                conditions: [],
                rabbitmqNodes: [],
                kafkaProducerBrokers: [],
                kafkaProducerSaslOptions: { mechanism: "None" },
                active: true,
                weight: (groups.length + 1) * 1000,
            };
            groupMonitor.name = groupName;
            groupMonitor.description = marker;
            groupMonitor.parent = null;
            groupMonitor.type = "group";
            groupMonitor.active = true;
            groupMonitor.id = existing ? existing.id : undefined;
            normalizeMonitorPayload(groupMonitor);
            const result = existing
                ? await emitMutation(socket, readOnly, "editMonitor", groupMonitor)
                : await emitMutation(socket, readOnly, "add", groupMonitor);
            if (!result || !result.ok) {
                throw new Error(`Kuma group sync failed for ${groupName}: ${result?.msg || "unknown error"}`);
            }
            const groupMonitorID = Number(result.monitorID || existing?.id);
            if (!Number.isInteger(groupMonitorID) || groupMonitorID <= 0) throw new Error(`Kuma returned invalid group monitor ID for ${groupKey}`);
            const publicGroup = { name: groupName, monitorList: [] };
            groupsByID.set(groupKey, publicGroup);
            groupMonitorByID.set(groupKey, groupMonitorID);
            groups.push(publicGroup);
            existingGroupByMarker.delete(marker);
        }

        for (const monitor of existingGroupByMarker.values()) {
            if (monitor.active !== false) {
                const paused = await emitMutation(socket, readOnly, "pauseMonitor", monitor.id);
                if (!paused || !paused.ok) throw new Error(paused?.msg || `Kuma group disable failed for ${monitor.id}`);
            }
        }

        const seenMarkers = new Set();
        const monitorStates = [];
        for (const source of input.manifest.monitors || []) {
            const marker = `meowai-deploy:${input.deployment_id}:source-monitor:${source.id}`;
            const existing = existingByMarker.get(marker);
            const groupKey = String(source.group_id || source.group || "default");
            const parentID = groupMonitorByID.get(groupKey);
            const desired = desiredMonitor(source, existing, input, parentID);
            if (existing && monitorDrifted(existing, desired.monitor) && !input.force) {
                throw new Error(`managed Kuma monitor ${existing.id} drifted; rerun sync with --force`);
            }
            let result;
            if (existing) {
                result = await emitMutation(socket, readOnly, "editMonitor", desired.monitor);
            } else {
                result = await emitMutation(socket, readOnly, "add", desired.monitor);
            }
            if (!result || !result.ok) throw new Error(result?.msg || `Kuma monitor sync failed for ${source.id}`);
            const monitorID = Number(result.monitorID || existing?.id);
            if (!Number.isInteger(monitorID) || monitorID <= 0) throw new Error(`Kuma returned invalid monitor ID for ${source.id}`);
            seenMarkers.add(marker);
            const group = groupsByID.get(groupKey);
            group.monitorList.push({ id: monitorID, sendUrl: false });
            monitorStates.push({
                source_monitor_id: String(source.id),
                kuma_monitor_id: monitorID,
                config_sha256: configHash({ ...source, id: source.id, url: desired.url, interval: desired.monitor.interval, timeout: desired.monitor.timeout, maxretries: desired.monitor.maxretries, active: desired.monitor.active, name: source.name }, input.status_key),
                enabled: desired.monitor.active !== false,
            });
        }

        for (const [marker, monitor] of existingByMarker.entries()) {
            if (seenMarkers.has(marker)) continue;
            if (monitor.active !== false) {
                const paused = await emitMutation(socket, readOnly, "pauseMonitor", monitor.id);
                if (!paused || !paused.ok) throw new Error(paused?.msg || `Kuma monitor disable failed for ${monitor.id}`);
            }
            monitorStates.push({
                source_monitor_id: marker.split(":").pop(),
                kuma_monitor_id: Number(monitor.id),
                config_sha256: "",
                enabled: false,
            });
        }

        const currentPage = {
            ...pageConfig,
            slug: input.status_page_slug,
            title: input.website_name,
            description: input.manifest.page_description || "",
            theme: input.manifest.theme || "auto",
            autoRefreshInterval: 60,
            logo: pageConfig.icon || "",
            showTags: false,
            domainNameList: [],
            customCSS: null,
            footerText: null,
            showPoweredBy: true,
            analyticsId: null,
            analyticsScriptUrl: null,
            analyticsType: null,
            showCertificateExpiry: false,
            showOnlyLastHeartbeat: false,
            rssTitle: null,
        };
        const saved = await emitMutation(socket, readOnly, "saveStatusPage", input.status_page_slug, currentPage, currentPage.logo, groups);
        if (!saved || !saved.ok) throw new Error(saved?.msg || "Kuma status page save failed");

        return {
            ok: true,
            page_slug: input.status_page_slug,
            monitor_count: (input.manifest.monitors || []).length,
            disabled_count: monitorStates.filter((monitor) => !monitor.enabled).length,
            monitors: monitorStates,
        };
    } finally {
        socket.close();
    }
}

async function main(input) {
    try {
        const result = await sync(input);
        process.stdout.write(JSON.stringify(result));
    } catch (error) {
        process.stdout.write(JSON.stringify({ ok: false, error: error.message || String(error) }));
    }
}
