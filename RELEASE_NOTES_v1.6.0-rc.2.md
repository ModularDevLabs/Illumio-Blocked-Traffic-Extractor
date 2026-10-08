# v1.6.0-rc.2 Analysis View Persistence

Testing prerelease of the standalone Traffic Extractor. It remains localhost-only and does not replace stable v1.5.0. The traffic recovery and large-CSV import improvements from [RC1](https://github.com/ModularDevLabs/Illumio-Blocked-Traffic-Extractor/releases/tag/v1.6.0-rc.1) are included.

## Analysis view persistence

- Heatmaps retain the active dimension, source and destination filters, selected cell, protocol and port drilldown filters, search text, and hide-empty setting when navigating away and returning. Each dimension keeps its own selections.
- Analytics retain pivot selections and collapsed sections. Executive reports retain chart ranges, service and relationship selections, comparison months, export-section choices, and unsaved report edits.
- Navigation, browser refresh, and the page's Refresh button preserve these choices for the current analysis. A successful CSV import, explicit saved-dataset reload, or completed extraction starts a fresh analysis, including when the same files are loaded again.
- Failed imports and report-setting saves do not reset the current analysis view. Theme preferences remain independent.

View choices are stored in the current browser tab's session, not as permanent saved views. Closing the tab ends that session. Use Save Report Settings to retain report metadata with a saved dataset. If browser storage is unavailable, controls still work, but choices cannot be retained across navigation.

## Reporting fixes

- Port identifiers display without thousands separators throughout heatmap drilldowns, analytics pivots, and executive service cards: `9300`, not `9,300`. Flow and connection counts keep their normal numeric formatting.
- Drilldown controls remain available when the selected protocol and port combination has no matching rows.
- Downloaded executive HTML includes the current chart selections and report edits, and remains interactive without sharing live browser state.
- Older overlapping refresh responses cannot replace a newer analysis. Invalid stored preferences fall back safely.

## Downloads

Versioned binaries are attached for Windows amd64, Linux amd64, Intel macOS, and Apple Silicon macOS. The executable name and application footer identify the release candidate.
