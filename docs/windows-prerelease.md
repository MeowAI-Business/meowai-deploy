# Windows prerelease checklist

This checklist is for a release candidate of the Windows amd64 control client. It must use a
local mock source or a disposable test source and a disposable Linux target. Do not use the
production source URL.

## Automated evidence

- [x] `cargo fmt --all -- --check`
- [x] `cargo test --locked` on the development host
- [x] `cargo clippy --locked --all-targets -- -D warnings`
- [x] `cargo xwin check --locked --target x86_64-pc-windows-msvc`
- [x] Fake `ssh`/`scp` process coverage for BatchMode, host-key and upload arguments
- [x] PowerShell installer source contract and checksum handling tests
- [x] CI matrix for Ubuntu, macOS and Windows, including a Windows mock release installer
- [x] Release workflow YAML includes Linux/macOS tarballs, Windows ZIP and one checksum list
- [x] Secret-pattern scan has no findings

## Manual evidence deferred to unified W/U acceptance

- [ ] Windows 10/11 Explorer double-click opens the loopback WebUI and default browser
- [ ] `cmd.exe`, PowerShell 5.1 and PowerShell 7 UTF-8, colors, no-color and narrow-terminal output
- [ ] OpenSSH capability installation, UAC prompts, user PATH refresh and running-exe update behavior
- [ ] Windows control client completes onboard, status, sync, clean, resume and rollback against a
      disposable Linux amd64 host
- [ ] Host-key confirmation, key/agent authentication and remote permission failures show stable
      user-facing errors without secrets

The manual items are intentionally not treated as automated passes. They are collected for the
user's unified acceptance after Windows and WebUI implementation is complete.
