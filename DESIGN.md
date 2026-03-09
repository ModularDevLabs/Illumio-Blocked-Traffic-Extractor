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
- **Automation:** Populates a live-search/autocomplete cache in the browser memory to prevent user typos and ensure query validity.

### 3.2. Traffic Extraction Engine
- **Decision Filter:** Strictly filters for `policy_decisions: ["blocked"]`.
- **Chronological Sequencing:** Uses a worker pool (3 concurrent slots) to process the requested date window from the most recent day backwards.
- **PCE Schema Compliance:** Ensures all mandatory fields (`query_name`, `services`, `exclude`) are present in every request to prevent HTTP 406 errors.
- **Resilience:** Automatic 60-second cooldown on HTTP 429 (Rate Limit) and recursive retries for failed chunks.
- **Service Filtering:** Supports both Illumio service references and direct protocol/port filters such as `TCP:445` and `UDP:5355`.

### 3.3. Data Aggregation & Deduplication
- **Unique Connections:** The tool treats a unique tuple of (Src IP, Dst IP, Port, Protocol, and all Labels) as a single "Unique Connection."
- **Cross-Day Merging:** Identical connections found on different days are merged into a single CSV row.
- **Flow Summing:** The `Flows` column represents the mathematical sum of all connections for that unique tuple across the full requested window.
- **Timestamp Tracking:** Records both the `First Detected` and `Last Detected` instances for each merged record.

### 3.4. Analytics and Review
- **Summary Route:** `/summary`
- **Executive Route:** `/executive-summary`
- **In-Memory Analytics:** After a successful fetch, the backend derives analytics state from the aggregated flow set.
- **Views:** Port/protocol summary, environment cross-talk, app-to-app matrix, heatmaps, top talkers, external/unmanaged summaries, and a separate executive-summary page.
- **Presentation Themes:** The application supports shared dark and Illumio-inspired dark/light palettes without changing the underlying analytics dataset.
- **CSV Re-Import:** Previously generated CSV files from this tool can be uploaded to rebuild the analytics dashboard without rerunning the query.

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
