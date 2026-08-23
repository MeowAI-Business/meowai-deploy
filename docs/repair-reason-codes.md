# Repair Reason Codes

| Code family | Automatic action | Manual boundary |
| --- | --- | --- |
| `TARGET_CREDENTIAL_*` | Rebuild env or rotate installation credentials | Identity mismatch |
| `TARGET_COMPOSE_*` | Reconcile the managed Compose template | Unknown resources or mounts |
| `TARGET_AGENT_*` | Repair the approved updater agent | Missing signed bundle |
| `TARGET_SERVICE_*` | Restart the smallest managed service set | Dependency or data health failure |
| `TARGET_IMAGE_DRIFT` | Apply the approved signed structural release after B2 | Missing/blocked release authorization |
| `PUBLIC_ENDPOINT_*` | Refresh monitoring and probe | Persistent endpoint identity/TLS failure |
| `SOURCE_UNREACHABLE` / `LOCAL_SESSION_REAUTH_REQUIRED` | None | Re-authenticate or restore control-plane access |
| `DATA_SCHEMA_UNKNOWN` / `DATA_IDENTITY_CHANGED` | None | Verify data and migration compatibility manually |
| `DATA_ENCRYPTED_WITH_LOST_KEY` | Rotate installation credentials only | Recover business ciphertext from the original key |

Unknown codes are preserved in JSON and stop automatic execution when no typed
handler exists.
