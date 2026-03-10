# Design Document: Illumio Blocked Traffic Extractor

## 1. Objective
To provide a stable, cross-platform standalone tool that extracts a user-selected number of days of "Reported Policy Decision: Blocked" traffic from the Illumio PCE. The tool segments queries into 1-day chunks to ensure PCE stability and avoid API timeouts, merges the results into a structured CSV, and exposes an in-app analytics dashboard for review.

## 2. Technical Architecture
- **Language:** Go (Golang) - Compiled to single binaries for Windows, Linux, and MacOS.
- **UI:** Embedded Web Interface (HTML/JS/Tailwind) served via a local Go web server.
- **Themes:** The extractor, analytics dashboard, and executive summary share a browser-persisted theme selection with `Dark`, `Illumio Dark`, and `Illumio Light` options.
- **Hosting Model:** Runs either locally on `127.0.0.1:8080` by default or as a centrally hosted web service via configurable host/port flags and env vars.
- **Portability:** 100% Go implementation (no CGO) to ensure flawless cross-compilation from a single build environment.
- **Persistence:** Local JSON file (`pce_profiles.json`) stores PCE credentials and query configurations.

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
- **Chronological Sequencing:** Uses a worker pool (3 concurrent slots) to process the requested date window from the most recent day backwards.
- **PCE Schema Compliance:** Ensures all mandatory fields (`query_name`, `services`, `exclude`) are present in every request to prevent HTTP 406 errors.
- **Resilience:** Automatic 60-second cooldown on HTTP 429 (Rate Limit) and recursive retries for failed chunks.
- **Service Filtering:** Supports both Illumio service references and direct protocol/port filters such as `TCP:445` and `UDP:5355`.
- **Selector Hardening:** Unknown source, destination, and exclusion values are only treated as IP filters when they parse as valid IP/CIDR values; otherwise they are skipped and logged as warnings.
- **Connection Test:** The UI connection check uses a lightweight authenticated API request rather than a full discovery collection load.

### 3.3. Data Aggregation & Deduplication
- **Unique Connections:** The tool treats a unique tuple of (Src IP, Dst IP, Port, Protocol, and all Labels) as a single "Unique Connection."
- **Cross-Day Merging:** Identical connections found on different days are merged into a single CSV row.
- **Flow Summing:** The `Flows` column represents the mathematical sum of all connections for that unique tuple across the full requested window.
- **Timestamp Tracking:** Records both the `First Detected` and `Last Detected` instances for each merged record.

### 3.4. Analytics and Review
- **Summary Route:** `/summary`
- **Executive Route:** `/executive-summary`
- **In-Memory Analytics:** After a successful fetch, the backend derives analytics state from the aggregated flow set.
- **Views:** Port/protocol summary, an environment-service pivot table, environment cross-talk, app-to-app matrix, top talkers, external/unmanaged summaries, a dedicated `/heatmaps` explorer page with drilldowns, and a separate executive-summary page.
- **Interaction Model:** The detailed analytics page allows each major section to be collapsed independently, with the browser persisting the user's last expanded/collapsed state.
- **Presentation Themes:** The application supports shared dark and Illumio-inspired dark/light palettes without changing the underlying analytics dataset.
- **CSV Re-Import:** Previously generated CSV files from this tool can be uploaded to rebuild the analytics dashboard without rerunning the query, and the summary API disables response caching so imported analytics are shown immediately.
- **Heatmap Drilldown:** The heatmap explorer renders full environment, application, or combined environment/application matrices from the complete analytics dataset and uses pair-level protocol/port aggregates for click-through drilldown, with pivot-style multi-select filters for both the matrix and the drilldown table.

## 4. CSV Schema
The CSV is dynamically structured based on the PCE's label keys:
`First Detected` | `Last Detected` | `Source IP` | `Src [Key1]` | `Src [Key2]`... | `Destination IP` | `Dst [Key1]`... | `Port` | `Protocol` | `Flows`

- **Protocol Mapping:** Resolves IANA numbers to names (e.g., 6 -> TCP, 17 -> UDP, 58 -> ICMPv6).
- **Label Alignment:** Dynamically creates columns for every label key found in the result set (Role, App, Env, Loc, etc.).

## 5. Validation Strategy
- **Unit Tests:** Cover request-building helpers such as direct protocol/port service parsing.
- **Live Smoke Test:** Optional live test uses a saved PCE profile to validate authentication, discovery, and a real Explorer query with explicit service filters.
- **Build Verification:** Binaries are rebuilt for Linux, Windows, macOS Intel, and macOS Apple Silicon after each code modification.

## 6. Known Challenges (Targeted for Resolution)
- **Count Mismatch:** Ensuring the "Unique Connection" count matches the PCE UI exactly by refining the `Include/Exclude` filter logic to handle OR (same key) and AND (different keys) operations correctly.
- **Schema Strictness:** Navigating the difference between `sec_policy/active` and root org-level API paths.
- **Credential UX:** Some browsers, especially Firefox, may still heuristically treat the credential section like a login form and offer to save credentials.
