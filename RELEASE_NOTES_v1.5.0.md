# v1.5.0 - Multi-CSV Trend Analysis and Executive Reporting

This release expands the extractor from a single-run reporting tool into a reusable analysis and delivery workflow while retaining an explicitly localhost-only web interface.

## Highlights

- Import and analyze multiple CSV exports as one dataset, with exact-row deduplication across files, named datasets, coverage-gap detection, and overlap guidance.
- Track month-over-month blocked flows, observed connections, active connections, and service trends with selectable time ranges and service series.
- Configure the primary and secondary label dimensions used throughout dashboards, heatmaps, and executive analysis, including custom Illumio label types.
- Build reusable report templates, schedule local report runs, compare run history, and deliver generated artifacts through Slack, Microsoft Teams, or generic webhooks.
- Export a configurable executive summary as interactive offline HTML or PDF, select which sections to include, and export individual sections, cards, and charts as PNG or SVG.
- Preserve the selected theme, source dataset identity, chart behavior, and version information in offline executive-summary exports.
- Use consistent navigation, theme controls, and collapsible sections throughout the extractor, analytics, heatmap, executive-summary, and automation workspaces.

## Data correctness

- Exact duplicate CSV rows are removed when combining files, while distinct observations and monthly occurrences remain represented in their respective months.
- Unique connections are calculated from normalized connection identity fields; monthly statistics count a connection in every month in which it was observed or active.
- Managed workload classification now uses the labels present on either endpoint, preventing labeled destination workloads from being incorrectly reported as external or unmanaged.
- Missing months appear as chart gaps rather than zero traffic, and overlapping source windows are identified without implying that exact duplicates remain in totals.

## Release artifacts

- `IllumioTrafficTool_v1.5.0_Linux`
- `IllumioTrafficTool_v1.5.0_Windows.exe`
- `IllumioTrafficTool_v1.5.0_MacOS_Intel`
- `IllumioTrafficTool_v1.5.0_MacOS_AppleSilicon`

The running version is also shown in the persistent page footer and exposed by the local version endpoint.

## Validation

- Go unit and race tests
- Go static analysis
- Frontend JavaScript syntax checks
- Cross-platform builds with embedded clean source metadata
- Browser verification across all five application workspaces and offline executive-summary exports
