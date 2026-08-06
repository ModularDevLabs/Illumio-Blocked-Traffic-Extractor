# v1.5.0-rc.2 - Executive Reporting and Trend Intelligence

This release candidate builds on the multi-CSV analysis introduced in `v1.5.0-rc.1` and is intended for validation before the final v1.5.0 release.

## Highlights

- Save imported analyses as named local dataset collections and reopen them without selecting the CSV files again.
- Detect missing months and overlapping source-file windows, and render missing coverage as chart gaps instead of zero activity.
- Add native SVG month-over-month flow and connection charts with 6-month, 12-month, and all-data ranges.
- Select and compare one or more services or primary-label relationships in interactive trend charts.
- Compare any two covered months for flow and connection changes, new risky services, new external destinations, and new relationships.
- Brand the executive summary with optional title, customer, prepared-by, notes, and logo metadata.
- Export self-contained executive HTML, print/save a light-theme PDF, download chart SVG/PNG files, and export monthly trend rows as CSV.
- Generate scheduled executive HTML and PDF artifacts, retain and download them with each run, and deliver them alongside the CSV.
- Preserve correct MIME types for CSV, HTML, and PDF delivery through supported webhook, Slack App, Teams Workflow, email, shared-folder, and SFTP destinations.
- Use one consistent application header, navigation order, theme selector state, and original Illumio palette across every workspace.

## Testing Guidance

- Import multiple monthly CSVs, save the result as a named dataset, restart the application, and reopen the saved collection.
- Confirm missing months appear as chart gaps and overlapping source windows produce a visible warning.
- Select several services and relationships, change the displayed range, and compare two different months.
- Test executive HTML, print/PDF, monthly CSV, SVG, and PNG downloads in each theme.
- Enable scheduled HTML and PDF artifacts on a template and verify run-history downloads, retention, and the configured delivery destination.

Validated with unit tests, Go race detection, `go vet`, frontend JavaScript parsing, runtime browser smoke tests, exact cross-page header measurements, and Linux, Windows, Intel macOS, and Apple Silicon macOS builds.
