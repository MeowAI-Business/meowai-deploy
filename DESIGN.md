# WebUI Design Direction

## Mode

Operate. The first screen is the deployment workflow, not a dashboard or marketing surface.

## Visual World

The WebUI follows the familiar NewAPI product language: compact system sans typography, restrained
neutral surfaces, blue primary actions, green completion states, thin dividers, and small-radius
controls. It automatically follows the operating system's light or dark color preference.

## Layout

- The page heading carries the close action; there is no separate application header.
- A conventional horizontal five-step indicator shows workflow position.
- One centered workflow panel contains the active form, validation, and navigation actions.
- The onboarding surface contains only the deployment workflow; daily management actions do not share this form.
- Narrow layouts keep all five steps visible and collapse multi-column fields to one column.

## Interaction

- Deployment location is a segmented choice between local and SSH deployment.
- Linux and macOS default to local deployment; unsupported platforms select SSH and disable local.
- SSH-specific fields appear only when SSH is selected.
- Entering site settings resolves the latest immutable image digest automatically and shows its relative image creation time when registry metadata provides one.
- Progress, failure recovery, and generated credentials remain in the same central workflow.
- Closing the WebUI stops the local server process; terminal interrupt signals do the same.

## Tokens

- Light background / surface: `#f7f7f8` / `#ffffff`
- Dark background / surface: `#191919` / `#242424`
- Primary: `#2563eb` light, `#3b82f6` dark
- Success: `#059669` light, `#34d399` dark
- UI font: Public Sans with native system and CJK fallbacks
- Radius: 6-8px for controls and framed surfaces

## Quality Bar

- Use both `impeccable` and `frontend-design` for future WebUI edits.
- Keep keyboard focus visible and motion reduced when requested.
- Keep copy user-facing; do not expose implementation, security, or test-stage commentary in the UI.
- Keep secrets out of persistent browser storage and visible URL state after bootstrap exchange.
