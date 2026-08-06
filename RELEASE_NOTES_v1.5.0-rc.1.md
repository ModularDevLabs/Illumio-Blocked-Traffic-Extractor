# v1.5.0-rc.1 - Multi-CSV Trend Analysis

This release candidate adds combined analytics for multiple CSV exports. It is intended for validation before the final v1.5.0 release.

## Highlights

- Select multiple CSV exports from either the main extractor page or the analytics dashboard.
- Stitch up to 60 files, within the combined 64 MiB upload limit, into one analytics dataset.
- Aggregate flow totals across all selected files while deduplicating matching connections in overall and monthly unique-connection counts.
- Preserve timestamp months so dashboards, heatmaps, and executive analysis can show trends across recurring exports.
- Reject files with identical content to prevent accidental duplicate imports.
- Accept the application's ISO timestamps as well as `MM/DD/YY hh:mm AM/PM` and RFC 3339 timestamps.
- Preserve the managed-workload destination classification fix from v1.4.0.

## Testing Guidance

Use monthly CSVs with non-overlapping report windows. Overlapping exports are accepted, but their flow totals are additive and can count the same observed flows more than once.

Tested with unit tests, Go race detection, `go vet`, `govulncheck`, frontend JavaScript parsing, cross-platform builds, and the previously reported managed-destination sample CSV.
