# Illumio Blocked Traffic Extractor

A local desktop-style Go application for extracting blocked traffic from an Illumio PCE, exporting it as CSV, and reviewing the results through detailed, heatmap, and executive analytics views.

Analytics dimensions are configurable from the PCE's discovered label types. The traditional `env` and `app` views remain the defaults, while custom keys such as `BU`, `region`, or `division` can be selected as the primary or secondary dimension and are carried through profiles, dashboards, heatmaps, executive summaries, and CSV re-import. Multiple CSV exports can be imported into named, reusable datasets with coverage-gap and overlap detection, combined analysis, month-over-month charts, multi-service and relationship selectors, and period comparisons.

The local Automation workspace at `/automation` adds reusable report templates, persistent scheduled runs, run-to-run change detection, CSV/HTML/PDF artifact retention, and delivery through generic webhooks, Slack, Teams Workflows, email, shared folders, or host-key-pinned SFTP. The executive view can compose HTML and print/PDF reports from selected sections, export any executive section as a presentation-ready PNG, export an interactive self-contained HTML report, download chart SVG/PNG files, and export monthly trend data as CSV. Major sections can be collapsed throughout every workspace, with their state remembered per page.

## Security model

The application is intentionally local-only. It binds exclusively to `127.0.0.1`, validates loopback HTTP hosts and same-origin state-changing requests, and does not provide remote hosting or multi-user authentication. Do not place it behind a reverse proxy or expose it through a port-forward.

Saved PCE profiles are stored in the current user's OS configuration directory with owner-only permissions. API keys and secrets are not returned by the profile-list API, but the profile file itself contains the credentials needed for unattended local use. Protect the local user account and its configuration directory accordingly.

## Run from source

Requirements:

- Go 1.25 or newer; the module pins the patched Go 1.26.5 toolchain for builds
- Network access from the local machine to the Illumio PCE

```bash
go run .
```

The application opens `http://localhost:8080` by default. You can change only the local port and browser behavior:

```bash
go run . -port 9090 -open-browser=false
```

Equivalent environment variables are `ITT_PORT` and `ITT_OPEN_BROWSER`.

Run a saved template without starting the browser:

```bash
./IllumioTrafficTool_Linux --run-template "Weekly Report"
```

Run only the persistent scheduler:

```bash
./IllumioTrafficTool_Linux --scheduler-only --open-browser=false
```

Only one process may use a user's profile and automation stores at a time. The provided startup installers normally run the full local application with browser opening disabled, so both the scheduler and UI remain available from one process.

See [USAGE.md](USAGE.md) for the complete operator guide and [DESIGN.md](DESIGN.md) for implementation details.

## Validation

```bash
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
```

The optional live PCE smoke test is documented in [USAGE.md](USAGE.md#11-validation-and-smoke-testing).

## Build assets and releases

Tailwind CSS is committed as a local asset so the UI works without CDN access. Regenerate it after changing frontend utility classes:

```bash
./scripts/build_css.sh
```

Build all supported release binaries with:

```bash
./scripts/build_release.sh
```

Generated binaries, credentials, CSV exports, and logs are excluded by `.gitignore`.

## Data integrity behavior

- Every extraction chunk is retried with bounded attempts.
- If any chunk ultimately fails, the run stops and does not create a partial CSV.
- Existing output files are never overwritten.
- CSV cells that spreadsheet applications could interpret as formulas are neutralized.
- PCE `first_detected` and `last_detected` values are retained independently.
- Multi-file imports remove exact duplicate rows found in different files and deduplicate matching unique connections. Differing aggregate rows from partially overlapping windows remain additive because exported CSVs do not carry per-flow event IDs.

## License

See [LICENSE](LICENSE).
