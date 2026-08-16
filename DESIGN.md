# WebUI Design Direction

## Mode

Operate. The first screen is the deployment workbench, not a marketing surface.

## Visual World

The interface is a deployment calibration bench: a pale work surface, graphite text,
signal orange for the current action, teal for verified state, and yellow for attention.
The left route spine shows the real five-step deployment sequence. The center surface is
the only place where the current task is completed. The right check rail keeps safety and
next-action context visible without becoming a dashboard.

## Tokens

- Ground: `#eef0eb`
- Paper: `#f7f8f4`
- Ink: `#1d2730`
- Signal orange: `#ed6a4b`
- Safety teal: `#1d9d95`
- Attention yellow: `#e0b73a`
- UI mono: system monospace stack
- Body: Avenir Next, Segoe UI, system sans-serif

## Signature

The route spine and check rail frame one calm current work surface. Progress is shown as a
physical route with stable nodes and a single moving fill, so the user always knows where
the deployment is and what can be done next.

## Quality Bar

- Use both `impeccable` and `frontend-design` for future WebUI edits.
- Keep keyboard focus visible and motion reduced when requested.
- Verify desktop and narrow mobile layouts in the browser.
- Keep secrets out of persistent browser storage and visible URL state.
