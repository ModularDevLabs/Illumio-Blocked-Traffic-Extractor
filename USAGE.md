# User Guide: Illumio Blocked Traffic Extractor

## 1. Getting Started
1.  Launch the executable (`IllumioTrafficTool_Linux`, `.exe`, or `_MacOS`).
2.  By default, your browser will automatically open to `http://localhost:8080`.
3.  Ensure the tool remains running in the background while you use the web interface.
4.  Use the theme toggle in the UI to switch between `Dark`, `Illumio Dark`, and `Illumio Light`. The app remembers the selected theme across pages.

## 2. Local-Only Operation
The tool is deliberately limited to local desktop use until authentication and per-user state are available. It always binds to `127.0.0.1` and rejects non-loopback HTTP hosts.

Examples:

```bash
./IllumioTrafficTool_Linux -port 9090 -open-browser=false
```

```bash
ITT_PORT=9090 ITT_OPEN_BROWSER=false ./IllumioTrafficTool_Linux
```

Notes:
-   Use `-port <number>` to choose the local port.
-   Use `-open-browser=false` when you do not want the browser opened automatically.
-   Remote binding flags are intentionally unavailable. Do not expose the app through a reverse proxy or port-forward.
-   State-changing browser actions require same-origin requests and expected HTTP methods.

## 3. Managing PCE Profiles
The tool allows you to save credentials for multiple Illumio environments.
-   **To Save a Profile:** Enter your PCE URL, Org ID, API Key, and Secret. Enter a name in the "New Profile Name" field and click **Save Current Config**.
-   **To Load a Profile:** Select the desired PCE from the dropdown menu.
-   **To Delete a Profile:** Select the profile from the dropdown and click **Delete**.
-   **Credential Storage:** Saved profiles are atomically written under the current user's OS configuration directory with owner-only permissions. Existing executable-directory profile files are migrated automatically and removed after a successful migration. Credentials are omitted from the browser profile-list response, but remain present in the protected local file so profiles can be reused.

Discovery notes:
-   **Load Policy Objects from PCE** now uses Illumio's asynchronous collection workflow so it can load full collections from larger PCEs instead of stopping at the first 500 objects.
-   Discovery now runs up to 3 collection jobs in parallel to reduce wait time on larger PCEs.
-   On large environments, discovery may still take longer because the PCE prepares full collection results before the UI autocomplete cache is populated.
-   Large-PCE discovery is allowed up to 15 minutes before timing out. If it does time out, no new discovery cache is saved.
-   The extractor reuses the most recently loaded discovery cache for the same PCE credentials so a fetch does not need to reload the full object inventory again.
-   Discovery progress is shown in the main-page log window so you can see each object type load as it completes.
-   Discovery also loads the available label types. These populate the primary and secondary analysis selectors, including custom types such as `BU`.

## 4. Running an Extraction
1.  **Select/Enter Credentials:** Ensure the PCE details are correct.
    -   **Test Connection:** Uses a lightweight authenticated API check instead of loading the full label inventory, so it remains responsive on larger PCEs. It also loads the PCE traffic database metrics panel on the main page, including server flow retention days and the oldest retained server-flow day when the metrics endpoint is available.
2.  **Choose Analysis Label Types:**
    -   Select a **Primary Dimension** and a different **Secondary Dimension** after loading policy objects.
    -   The defaults are `env` and `app`. For a business-unit-led report, select `BU` as primary and, for example, `app` as secondary.
    -   These choices control dashboard matrices, heatmap modes, generated executive findings, and scorecards. They are also saved with PCE profiles.
3.  **Define Filters:**
    -   **Sources/Destinations:** Enter label names (e.g., `App: DB`) or IP addresses. Separate multiple items with commas.
    -   **Services:** Enter specific service names from the PCE (e.g., `SSH, MySQL`) or explicit protocol/port filters (e.g., `TCP:445, UDP:5355`). Leave empty to pull all services.
    -   **Add Risky Services:** Click this button to append the Illumio ransomware risky-services set to the Services field. Entries marked `TCP/UDP` are added as separate filters.
    - **Exclusions:** Enter labels or IPs you wish to exclude from either the Source or Destination side.
    - **Days To Fetch:** Choose how many days of blocked traffic to query. The default is 90.
    - **Chunk Interval:** Choose how the requested time window is split before querying the PCE. The default is `1 day`, with smaller options down to `5 minutes`.
    - **Start Date / End Date:** Optionally set an explicit query window using `YYYY-MM-DD`. If both dates are provided, the app fetches that exact inclusive date range and ignores `Days To Fetch`.
    - **Unknown selectors:** If a source, destination, or exclusion value does not match a discovered object and is not a valid IP or CIDR, it will be skipped and logged as a warning instead of being sent to the PCE as an invalid IP.
4.  **Configure Export:**
    -   **Target Filename:** Choose a name for your CSV (e.g., `march_report.csv`).
    -   **Target Folder:** Enter the **absolute path** to the folder where the file should be saved (e.g., `C:\Users\Admin\Desktop` or `/home/user/Downloads`).
5.  **Start:** Click **Start Fetch**.

## 5. Monitoring & Controls
-   **Progress Bar:** Shows the percentage of the requested time window completed.
-   **Status Label:** Displays how many days have been processed and the total flow count gathered so far.
-   **Log Box:** Provides a detailed, real-time feed of API interactions and errors.
-   **Discovery Progress:** When loading policy objects, the log box shows staged progress for labels, services, IP lists, and other discovery collections.
-   **Cancel Button:** Use this to stop the extraction immediately. Cancelled runs and runs with any ultimately failed chunk do not save partial data.
-   **Output Safety:** Existing files are not overwritten, filenames cannot contain directory traversal components, and spreadsheet-formula-like cells are neutralized in exported CSVs.

## 6. Analytics Dashboard
After a successful fetch, use the link on the main page to open `/summary`.

Available analytics views:
-   Port / protocol summary
-   Monthly port / protocol breakdown
-   Primary-dimension service pivot table with multi-select source filtering
-   Primary-dimension cross-talk matrix
-   Secondary-dimension matrix
-   Heatmap-style primary and secondary matrices
-   Top talkers
-   External / unmanaged traffic summaries

Notes:
-   Each major section on `/summary` can be collapsed or expanded independently. The page remembers your section state in the browser.
-   The monthly breakdown groups blocked flows by `YYYY-MM` and then shows the protocol/port rows contributing to each month.
-   `Flows` reflects observed monthly volume. `Unique Connections` reflects connections with observed traffic in that month. `Active Connections` reflects connections whose first/last detected span includes that month, even if the observed flow volume was concentrated in a different month.
-   The primary service pivot lets you select one or more source label values and see destination-label flow totals broken out by protocol and port.
-   Heatmaps exclude the `External/Unmanaged` bucket by default so labeled relationships are easier to read.
-   Labeled unmanaged endpoints are grouped by their actual labels where possible.

## 7. Heatmap Explorer
Use `/heatmaps` for a dedicated full-data heatmap view.

This page provides:
-   primary, secondary, and combined primary + secondary heatmap modes, named for the selected PCE label types
-   pivot-style multi-select source and destination filters
-   full heatmaps built from the complete analytics dataset rather than the reduced top-N dashboard view
-   click-to-drilldown so a selected heatmap cell shows the protocol/port rows that make up that flow total
-   pivot-style multi-select protocol and port filters inside the drilldown panel

Notes:
-   `Hide Empty Rows/Cols` is enabled by default to keep large matrices readable.
-   The drilldown panel updates based on the currently selected heatmap mode and filters.

## 8. Executive Summary
Use `/executive-summary` for a presentation-ready view of the currently loaded dataset.

This page is intended for leadership or slide-friendly review and highlights:
-   headline summary cards
-   latest-month trend cards for observed flows, active connections, and month-over-month change
-   auto-generated top findings
-   risky services by blocked flow volume
-   persistent blocked service patterns across months
-   latest-month new port / protocol pairs
-   top primary-dimension cross-talk relationships
-   external / unmanaged destination spotlight
-   primary-dimension scorecards with simple risk ranking

It uses the same underlying analytics dataset as `/summary`, but presents it in a simpler executive format.
It also includes the shared app theme toggle so you can switch between `Dark`, `Illumio Dark`, and `Illumio Light`.

## 9. CSV Re-Import
The analytics page can rebuild its visuals from a previously exported CSV from this tool.

1.  Open `/summary`.
2.  Enter the primary and secondary label types represented by the CSV (for example, `BU` and `app`).
3.  Choose a CSV generated by this application.
4.  Click **Import CSV**.

You can also start this flow directly from the main extractor page:

1.  Use the **Upload Existing CSV** section.
2.  Select the primary and secondary analysis label types above the upload panel.
3.  Choose a CSV generated by this application.
4.  Click **Upload CSV**.
5.  The app will import the file and take you directly to `/summary`.

Notes:
-   Import expects the CSV schema generated by this tool and requires `Src <label type>` / `Dst <label type>` columns for both selected dimensions. Header matching is case-insensitive.
-   This is useful if the app was restarted or the original in-memory analytics state is no longer present.
-   After import, `/summary` now forces a fresh analytics reload so the imported dataset appears immediately instead of reusing an older empty-state response.

## 10. Validation and Smoke Testing
Two test layers are available:

-   `go test ./...`
    - Runs unit tests, including service-filter parsing.
-   `./smoke_test.sh`
    - Runs the unit tests plus a live Illumio API smoke test using `pce_profiles.json`.

Optional environment variables:
-   `PCE_PROFILE_PATH`
    - Override the profile file path for the live smoke test. When omitted, the OS configuration-directory profile store is used.
-   `PCE_PROFILE_NAME`
    - Select a specific profile from the JSON file.
-   `GO_BIN`
    - Override the Go binary path used by `smoke_test.sh`.

The live smoke test validates:
-   PCE authentication
-   discovery calls
-   Explorer acceptance of direct service filters like `TCP:445` and `UDP:5355`

## 11. Troubleshooting
-   **HTTP 401/403:** Your API Key or Secret is incorrect, or the user does not have permission to run traffic queries.
-   **HTTP 404:** The PCE URL or Org ID is incorrect.
-   **Connection Refused:** Ensure your machine has network access to the PCE URL provided.
-   **Remote Users Cannot Reach the App:** This is intentional. The current release is local-only and has no remote hosting mode.
-   **0 Flows Found:** Verify your label names. Labels must match the exact case and spelling used in the PCE.
-   **Heatmap looks too large:** Use the source and destination filters or leave `Hide Empty Rows/Cols` enabled.
-   **Live smoke test cannot connect:** Ensure the local machine has network access to the PCE and that the selected saved profile is still valid.
