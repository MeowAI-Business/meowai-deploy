# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

delegated: Rust/axum local server with an embedded React/TypeScript client, because the existing
control runtime is Rust and the deployment flow must be available offline after installation.

## Users

Based on the deployment plan: customers using Windows 10/11, Linux, or macOS as a control computer.
The primary WebUI user is a customer who does not want to operate a command-line deployment flow.
Operators and support engineers also need a concise status and recovery view.

## Product Purpose

Based on the deployment plan: guide a customer through source account setup, SSH target checks,
downstream site configuration, deployment, status, synchronization, cleanup, and rollback. Success
means the customer can complete or recover a deployment without the WebUI owning a second business
implementation or leaking credentials to the browser.

## Positioning

The WebUI is a loopback adapter over the same typed deployment application core as the CLI. It is
not a hosted dashboard and never exposes the control server beyond the local machine.

## Operating Context

The browser talks to an HTTP server started by `meowai-deploy web` or a double click. It listens on
`0.0.0.0` and a random available port by default, with explicit host and port overrides for local
or LAN access. A short-lived bootstrap token in the URL fragment is exchanged for an HttpOnly
session cookie. The server then calls the shared application layer and either deploys locally on a
supported host or uses the system OpenSSH client to reach another server. Production source URLs
are excluded from tests.

## Capabilities and Constraints

- Configurable binding, single-instance behavior, one-time bootstrap exchange, CSRF and Origin/Host
  checks, strict security headers, no-cache responses, SSE operation events, and graceful timeout.
- Source and optional SSH passwords may exist only in the current form state and request body. No
  credential may enter URLs, persistent browser storage, telemetry, logs, or static assets.
- The UI covers onboarding, preview, deployment progress, cancellation/recovery, status, sync,
  clean, rollback, and clear failure recovery.
- Linux and macOS can deploy locally or over SSH. Windows is an SSH control client only; local
  deployment is rejected before source credentials are read. Real Windows double-click, UAC,
  browser, and Windows-to-Linux acceptance remain manual.

## Brand Commitments

Name: `meowai-deploy`. Existing CLI copy is plain, direct Chinese UI text with stable error codes.
No existing WebUI visual identity or brand assets were found in this worktree.

## Evidence on Hand

The shared typed application modules under `src/application/` are the source of truth for workflow
contracts. No production screenshots, logos, customer testimonials, or marketing claims are
available; the WebUI must not invent them.

## Product Principles

- Make the next safe deployment action obvious.
- Show state and recovery paths before asking for another credential.
- Keep secrets in the local server and ephemeral session, never in browser state.
- Reuse the shared application core so CLI and WebUI cannot drift semantically.

## Accessibility & Inclusion

The WebUI must be keyboard usable, have visible focus, semantic labels, readable contrast, reduced
motion support, responsive layouts for narrow laptop/mobile browser widths, and clear error text.
