# Design Document: Illumio Blocked Traffic Extractor

## 1. Objective
To provide a stable, cross-platform standalone tool that extracts "Reported Policy Decision: Blocked" traffic from the Illumio PCE for either a user-selected number of trailing days or an explicit inclusive date range. The tool segments queries into 1-day chunks to ensure PCE stability and avoid API timeouts, merges the results into a structured CSV, and exposes an in-app analytics dashboard for review.

## 2. Technical Architecture
- **Language:** Go (Golang) - Compiled to single binaries for Windows, Linux, and MacOS.
- **UI:** Embedded Web Interface (HTML/JS/precompiled Tailwind CSS) served via a local Go web server without CDN dependencies.
- **Themes:** The extractor, analytics dashboard, and executive summary share a browser-persisted theme selection with `Dark`, `Illumio Dark`, and `Illumio Light` options.
- **Hosting Model:** Local-only. The server always binds to `127.0.0.1`; remote hosting remains deferred until authentication and per-user state exist.
- **Request Hardening:** State-changing API routes enforce expected HTTP methods and origin evidence. The server validates loopback hosts, applies security headers with per-response script nonces, limits request bodies, and configures HTTP timeouts.
- **Portability:** 100% Go implementation (no CGO) to ensure flawless cross-compilation from a single build environment.
- **Persistence:** A JSON profile file under the current user's OS configuration directory stores PCE credentials and query configurations.
- **Automation Persistence:** A separate owner-only `automation.json` store contains templates, schedules, delivery credentials, queued work, run history, comparison snapshots, and delivery results. Templates reference PCE profiles by name and never duplicate PCE credentials.
- **Single Process Ownership:** An OS-level non-blocking file lock prevents multiple UI, scheduler, or headless processes from mutating the same per-user stores or running overlapping extractions.
- **Local Credential File Permissions:** Profile changes use atomic replacement and owner-only directory/file permissions. Profile-list responses omit API keys and secrets.

## 3. Core Features
### 3.1. Policy Object Discovery
- **Endpoint:** `/api/discovery`
- **Scope:** Loads Labels, Label Groups, IP Lists, User Groups, Virtual Services, and Virtual Servers.
- **Collection Strategy:** Uses Illumio asynchronous GET collection jobs for discovery collections so larger PCEs are not truncated at the default 500-object response limit.
- **Concurrency Model:** Runs discovery collection fetches with a bounded worker pool (3 concurrent collection jobs) to reduce wall-clock load time without fully flooding the PCE.
- **Timeout Model:** Discovery allows up to 15 minutes for large collection loads before failing without updating the cached object inventory.
- **Cache Reuse:** Extraction reuses the last successful discovery cache for the same PCE credential set so fetches can start without reloading the full policy-object inventory.
- **Operator Feedback:** Discovery progress is streamed into the main-page log window so long-running large-PCE collection loads remain visible to the user.
- **Automation:** Populates a live-search/autocomplete cache in the browser memory to prevent user typos and ensure query validity.

### 3.2. Traffic Extraction Engine
- **Decision Filter:** Strictly filters for `policy_decisions: ["blocked"]`.
- **Chronological Sequencing:** Uses a worker pool (3 concurrent slots) to process the requested date window from the end of the selected range backwards in configurable time chunks.
- **Chunk Sizing:** The extraction window can be split into configurable chunks from `1 day` down to `5 minutes`, while the final CSV still merges matching connections across the full requested range.
- **PCE Schema Compliance:** Ensures all mandatory fields (`query_name`, `services`, `exclude`) are present in every request to prevent HTTP 406 errors.
- **Resilience:** Automatic cooldown on HTTP 429 responses, bounded query-creation retries, per-chunk deadlines, bounded chunk retries, and a 24-hour overall run deadline.
- **Completeness Guarantee:** If any chunk ultimately fails, extraction aborts and no partial CSV is reported as successful.
- **Reusable Runner:** Interactive, queued, scheduled, and `--run-template` executions share the same validated extraction path. The persistent worker serializes jobs and waits for an active interactive run instead of overlapping it.
- **Restart Recovery:** Queued jobs survive restarts; a job left in `running` state is marked failed with an interruption reason. Schedule policy determines whether one missed run is queued after startup or skipped.
- **Service Filtering:** Supports both Illumio service references and direct protocol/port filters such as `TCP:445` and `UDP:5355`.
- **Selector Hardening:** Unknown source, destination, and exclusion values are only treated as IP filters when they parse as valid IP/CIDR values; otherwise they are skipped and logged as warnings.
- **Connection Test:** The UI connection check uses a lightweight authenticated API request rather than a full discovery collection load.
- **Traffic DB Metrics:** The main page can query the PCE traffic flow database metrics endpoint and show current server retention days plus the oldest retained server-flow day.
- **Window Selection:** Users can run either a trailing `Days To Fetch` query or an explicit inclusive `Start Date` / `End Date` range.

### 3.3. Data Aggregation & Deduplication
- **Unique Connections:** The tool treats source/destination IPs, port, protocol, workload identities, process/FQDN, and canonical source/destination label sets as the unique connection identity.
- **Cross-Day Merging:** Identical connections found on different days are merged into a single CSV row.
- **Flow Summing:** The `Flows` column represents the mathematical sum of all connections for that unique tuple across the full requested window.
- **Timestamp Tracking:** Records both the `First Detected` and `Last Detected` instances for each merged record.
- **Spreadsheet Safety:** Formula-like text cells are neutralized on export and restored when re-imported by the tool.

### 3.4. Analytics and Review
- **Summary Route:** `/summary`
- **Executive Route:** `/executive-summary`
- **In-Memory Analytics:** After a successful fetch, the backend derives analytics state from the aggregated flow set.
- **Configurable Dimensions:** Discovery returns every PCE label type. The user selects two distinct analysis dimensions (default `env` and `app`), and profiles persist those choices. Internal legacy field names remain stable for API compatibility, while `primary_label_key` and `secondary_label_key` metadata tell every UI how to label the data.
- **Views:** Port/protocol summary, a monthly port/protocol breakdown, a primary-dimension service pivot, primary and secondary cross-talk matrices, top talkers, external/unmanaged summaries, a dedicated `/heatmaps` explorer page with drilldowns, and a separate executive-summary page.
- **Executive Framing:** The executive-summary page layers presentation-oriented rollups on top of the same analytics payload, including latest-month trend cards, generated narrative findings, risky-service concentration, persistent month-spanning service patterns, latest-month change detection for new port/protocol pairs, external concentration, and primary-dimension scorecards with a simple weighted risk ranking.
- **Interaction Model:** The detailed analytics page allows each major section to be collapsed independently, with the browser persisting the user's last expanded/collapsed state.
- **Presentation Themes:** The application supports shared dark and Illumio-inspired dark/light palettes without changing the underlying analytics dataset.
- **CSV Re-Import:** One or more previously generated CSV files from this tool can be uploaded with explicit primary/secondary label keys to rebuild the analytics dashboard without rerunning the query. Multi-file imports stitch records into one dataset, deduplicate matching connections for overall unique-connection analysis, and retain per-file timestamp months for trend views. Exact duplicate files are rejected; overlapping but non-identical export windows are accepted with a UI warning because their flow counts will be additive. Dimension column matching is case-insensitive, and the summary API disables response caching so imported analytics are shown immediately.
- **Heatmap Drilldown:** The heatmap explorer renders full primary, secondary, or combined matrices from the complete analytics dataset and uses pair-level protocol/port aggregates for click-through drilldown, with pivot-style multi-select filters for both the matrix and the drilldown table.
- **Monthly Breakdown:** Live fetches compute exact per-month port/protocol flow totals while processing daily chunks. The monthly table also tracks both observed unique connections and month-spanning active connections based on each merged connection's first/last detected timestamps. Imported CSVs preserve the same distinction using the recorded detection month for observed flows and the row's first/last detected timestamps for active-month coverage.

### Automation and Delivery

- **Templates:** Store filters, selected analytics dimensions, rolling lookback, chunking, filename tokens, output location, retention, schedule, alert policy, and destination references. Template export excludes IDs, timestamps, credentials, and destination associations; imports start disabled so local profiles and destinations can be reviewed before activation.
- **Schedules:** Daily, weekdays, weekly, monthly, and standard five-field cron schedules run in an explicit IANA timezone. Monthly schedules intentionally limit the day to 1–28 for deterministic behavior.
- **Artifacts:** Scheduled filenames support `{template}`, `{date}`, `{time}`, `{timestamp}`, and `{run_id}`. Creation and delivery refuse overwrites. Retention deletes only absolute artifact paths recorded for that same template.
- **Change Detection:** Each successful run records flow totals, external traffic, primary relationships, and protocol/port pairs. The next run derives flow percentage change plus newly observed relationships and services for conditional alerts.
- **Boundary Classification:** General top destinations and external/unmanaged destinations are maintained as separate aggregates. External destination rankings contain only records whose destination endpoint lacks workload classification; unmanaged sources do not cause a managed destination to enter that list.
- **Delivery Adapters:** Generic JSON/multipart webhooks, Slack incoming-webhook messages, Slack external file upload, Teams Workflow Adaptive Cards with optional base64 file data, TLS-capable SMTP attachments, shared-folder copies, and SFTP uploads.
- **Outbound Safety:** Webhook URLs require HTTPS unless private-network access is explicitly enabled. DNS results and redirects are checked against loopback, private, link-local, multicast, and unspecified address ranges, and webhook connections bypass environment proxies so target validation cannot be delegated to a different resolver. SFTP requires a pinned host public key. Secrets are excluded from browser APIs and redacted from delivery failures.

## 4. CSV Schema
The CSV is dynamically structured based on the PCE's label keys:
`First Detected` | `Last Detected` | `Source IP` | `Src [Key1]` | `Src [Key2]`... | `Destination IP` | `Dst [Key1]`... | `Port` | `Protocol` | `Flows`

- **Protocol Mapping:** Resolves IANA numbers to names (e.g., 6 -> TCP, 17 -> UDP, 58 -> ICMPv6).
- **Label Alignment:** Dynamically creates columns for every label key found in the result set (Role, App, Env, Loc, etc.).

## 5. Validation Strategy
- **Unit Tests:** Cover request building, date/chunk behavior, origin and URL validation, output paths, CSV formula protection, client request boundaries, and first/last timestamp parsing.
- **Continuous Integration:** GitHub Actions runs tests and vet across Linux, Windows, and macOS, plus the race detector and `govulncheck` on Linux.
- **Live Smoke Test:** Optional live test uses a saved PCE profile to validate authentication, discovery, and a real Explorer query with explicit service filters.
- **Build Verification:** Binaries are rebuilt for Linux, Windows, macOS Intel, and macOS Apple Silicon after each code modification.

## 6. Known Challenges (Targeted for Resolution)
- **Count Mismatch:** Ensuring the "Unique Connection" count matches the PCE UI exactly by refining the `Include/Exclude` filter logic to handle OR (same key) and AND (different keys) operations correctly.
- **Schema Strictness:** Navigating the difference between `sec_policy/active` and root org-level API paths.
- **Future Hosted Mode:** Authentication, HTTPS deployment guidance, and per-user profiles/runs are required before remote binding can return.
- **Credential UX:** Some browsers, especially Firefox, may still heuristically treat the credential section like a login form and offer to save credentials.
