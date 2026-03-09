# Design Document: Illumio Blocked Traffic Extractor

## 1. Objective
To provide a stable, cross-platform standalone tool that extracts 90 days of "Reported Policy Decision: Blocked" traffic from the Illumio PCE. The tool segments queries into 1-day chunks to ensure PCE stability and avoid API timeouts, merging the results into a structured, pivot-ready CSV.

## 2. Technical Architecture
- **Language:** Go (Golang) - Compiled to single binaries for Windows, Linux, and MacOS.
- **UI:** Embedded Web Interface (HTML/JS/Tailwind) served via a local Go web server.
- **Portability:** 100% Go implementation (no CGO) to ensure flawless cross-compilation from a single build environment.
- **Persistence:** Local JSON file (`pce_profiles.json`) stores PCE credentials and query configurations.

## 3. Core Features
### 3.1. Policy Object Discovery
- **Endpoint:** `/api/discovery`
- **Scope:** Loads Labels, Label Groups, IP Lists, User Groups, Virtual Services, and Virtual Servers.
- **Automation:** Populates a live-search/autocomplete cache in the browser memory to prevent user typos and ensure query validity.

### 3.2. Traffic Extraction Engine
- **Decision Filter:** Strictly filters for `policy_decisions: ["blocked"]`.
- **Chronological Sequencing:** Uses a worker pool (3 concurrent slots) to process the 90-day window from the most recent day backwards.
- **PCE Schema Compliance:** Ensures all mandatory fields (`query_name`, `services`, `exclude`) are present in every request to prevent HTTP 406 errors.
- **Resilience:** Automatic 60-second cooldown on HTTP 429 (Rate Limit) and recursive retries for failed chunks.

### 3.3. Data Aggregation & Deduplication
- **Unique Connections:** The tool treats a unique tuple of (Src IP, Dst IP, Port, Protocol, and all Labels) as a single "Unique Connection."
- **Cross-Day Merging:** Identical connections found on different days are merged into a single CSV row.
- **Flow Summing:** The `Flows` column represents the mathematical sum of all connections for that unique tuple across the entire 90-day window.
- **Timestamp Tracking:** Records both the `First Detected` and `Last Detected` instances for each merged record.

## 4. CSV Schema
The CSV is dynamically structured based on the PCE's label keys:
`First Detected` | `Last Detected` | `Source IP` | `Src [Key1]` | `Src [Key2]`... | `Destination IP` | `Dst [Key1]`... | `Port` | `Protocol` | `Flows`

- **Protocol Mapping:** Resolves IANA numbers to names (e.g., 6 -> TCP, 17 -> UDP, 58 -> ICMPv6).
- **Label Alignment:** Dynamically creates columns for every label key found in the result set (Role, App, Env, Loc, etc.).

## 5. Known Challenges (Targeted for Resolution)
- **Count Mismatch:** Ensuring the "Unique Connection" count matches the PCE UI exactly by refining the `Include/Exclude` filter logic to handle OR (same key) and AND (different keys) operations correctly.
- **Schema Strictness:** Navigating the difference between `sec_policy/active` and root org-level API paths.
