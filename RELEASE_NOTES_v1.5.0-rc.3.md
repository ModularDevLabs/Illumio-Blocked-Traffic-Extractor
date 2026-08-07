# v1.5.0-rc.3 - Export Composition and Reporting Polish

This release candidate builds on the multi-file trend and executive reporting work in `v1.5.0-rc.2`. It focuses on import integrity, reusable executive exports, offline report reliability, and consistent section controls throughout the application.

## Highlights

- Remove exact duplicate CSV rows found in different imported files and report the number of rows and flows removed.
- Continue deduplicating matching unique connections while clearly identifying aggregate rows from partially overlapping windows that cannot be safely separated without per-flow event IDs.
- Keep downloaded executive HTML reports fully interactive offline, including themes, chart ranges, service and relationship selectors, collapsible sections, and image exports.
- Correct standalone HTML trend-chart sizing so service and relationship charts use the available report width.
- Add persistent collapse and expand controls to major sections across the Extractor, Analytics, Heatmaps, Executive Summary, and Automation workspaces.
- Add an Executive Summary Export Composer for selecting exactly which content sections appear in HTML and print/PDF exports.
- Save executive section selections with report metadata in named datasets.
- Add high-resolution PNG export for every executive section, including the report identity, coverage, overview, trends, findings, and scorecards.
- Preserve the active theme and selected chart context in section images while removing action buttons from the captured output.

## Testing Guidance

- Import CSVs with identical rows in more than one file and confirm the coverage panel reports the removed rows and flows.
- Import partially overlapping exports with differing aggregate rows and confirm the remaining additive-flow warning is shown.
- Select only a few sections in the Export Composer and verify that HTML and print/PDF output includes those sections plus the report identity.
- Download PNGs from overview, chart, and scorecard sections in each theme.
- Open a downloaded HTML report without the application running and verify themes, chart selectors, collapse controls, and section PNG exports remain functional.
- Collapse sections on every workspace, reload the pages, and confirm each page remembers its own state.

Validated with unit tests, Go race detection, `go vet`, frontend JavaScript parsing, live browser smoke tests, actual PNG and filtered standalone HTML downloads, and Linux, Windows, Intel macOS, and Apple Silicon macOS builds.
