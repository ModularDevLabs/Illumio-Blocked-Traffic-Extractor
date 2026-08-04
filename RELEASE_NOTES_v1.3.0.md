# Release Notes — v1.3.0

## Configurable analysis dimensions

- Added discovery-backed primary and secondary analytics label selectors, including custom PCE label types such as `BU`; selections persist in profiles and dynamically label dashboards, heatmaps, and executive analysis.
- Added dimension-aware CSV re-import with case-insensitive custom label-column matching.

## Security and deployment

- Restricted the application to `127.0.0.1`; remote hosting is deferred until authentication and per-user state are implemented.
- Added loopback-host validation, stricter same-origin checks, security response headers, HTTP server timeouts, and bounded request bodies.
- Removed API keys and secrets from the browser profile-list response.
- Moved profile storage to the user's OS configuration directory with atomic writes and owner-only permissions, including migration from the legacy executable directory.
- Validated PCE origins and blocked cross-origin asynchronous job URLs and redirects.
- Escaped PCE/CSV-derived frontend content, removed inline event handlers, added per-response script CSP nonces, and neutralized spreadsheet formula injection in CSV exports.

## Extraction correctness and reliability

- Parse and preserve independent PCE `first_detected` and `last_detected` timestamps.
- Include canonical source and destination labels in connection aggregation identity.
- Retry chunks with bounded attempts and abort without writing a partial CSV if any chunk fails.
- Reject concurrent extraction starts and enforce per-chunk and overall run deadlines.
- Refuse filename traversal, relative target directories, and accidental overwriting of existing CSV files.
- Bound PCE response sizes and clean up asynchronous queries with time-limited requests.

## Packaging and maintenance

- Replaced Tailwind and Google Fonts CDN dependencies with committed local CSS and system font fallbacks.
- Updated `golang.org/x/sys`, pinned the patched Go 1.26.5 toolchain, and added cross-platform CI, race testing, vet, and vulnerability scanning.
- Added a root README plus repeatable CSS and release build scripts.
- Expanded tests for security boundaries, output handling, aggregation labels, timestamp parsing, and asynchronous query cleanup.
