# v1.5.0-rc.4 - Theme Fidelity and Versioned Builds

This release candidate builds on the configurable executive exports introduced in `v1.5.0-rc.3`. It focuses on theme fidelity, finer-grained image exports, and making the running and downloaded application version immediately identifiable.

## Highlights

- Add individual high-resolution PNG export actions to the four latest-period metric cards: Observed Flows, Active Connections, Flow Change, and New Service Pairs.
- Preserve the source dashboard theme and dataset identity when downloading a standalone executive HTML report.
- Redraw all executive trend charts whenever the theme changes so chart panels, grids, labels, and point outlines stay synchronized with the page.
- Remember theme changes independently in downloaded offline reports.
- Correct executive select, option, input, and textarea colors across Dark, Illumio Dark, and Illumio Light themes.
- Add a small fixed footer to every workspace showing the exact version currently running.
- Retain the version footer in self-contained executive HTML reports when opened offline.
- Inject the release version into the application at build time and print it in startup output.
- Add a local `/api/version` endpoint for the shared version footer.
- Include the release version in downloadable executable names while retaining unversioned compatibility copies for existing local shortcuts and scripts.

## Release Assets

- `IllumioTrafficTool_v1.5.0-rc.4_Linux`
- `IllumioTrafficTool_v1.5.0-rc.4_Windows.exe`
- `IllumioTrafficTool_v1.5.0-rc.4_MacOS_Intel`
- `IllumioTrafficTool_v1.5.0-rc.4_MacOS_AppleSilicon`

## Testing Guidance

- Open each workspace and confirm the lower-left footer reports `v1.5.0-rc.4`.
- Export each latest-period metric card as PNG and confirm the action button does not appear in the captured image.
- Download executive HTML from each theme and confirm the offline report opens in that source theme with the same dataset name.
- Change themes in the offline report and verify every chart redraws immediately and the choice persists after reloading.
- Confirm the Range, service, relationship, and comparison selectors remain legible in both dark themes and the light theme.
- Confirm the version in each executable filename matches the version shown in the application footer.

Validated with unit tests, Go race detection, `go vet`, frontend JavaScript parsing, three-theme contrast checks, live browser checks across all five workspaces, standalone HTML download testing, and Linux, Windows, Intel macOS, and Apple Silicon macOS builds.
