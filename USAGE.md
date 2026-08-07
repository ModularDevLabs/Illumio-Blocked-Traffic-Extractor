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
-   Major sections throughout the extractor, analytics, heatmap, executive, and automation workspaces can be collapsed or expanded independently. Each page remembers its section state in the browser.
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
-   native month-over-month line charts with 6-month, 12-month, and all-data ranges
-   selectable multi-service and primary-relationship trend comparisons
-   comparisons between any two covered months, including newly observed risky services, external destinations, and relationships
-   source-file coverage, missing-month, and overlapping-window warnings

It uses the same underlying analytics dataset as `/summary`, but presents it in a simpler executive format.
It also includes the shared app theme toggle so you can switch between `Dark`, `Illumio Dark`, and `Illumio Light`.

Report configuration can add a customer name, title, prepared-by value, notes, and an optional logo. These values stay with a saved dataset. The **Export Composer** lets you include or omit each executive content section from **Export PDF / Print** and **Download HTML** output without hiding it from the live dashboard; the selection is retained with the report settings. Every executive section also has its own **Export PNG** action for presentation-ready image reuse. Chart controls can still download individual SVG and PNG charts, and **Download Monthly Data CSV** exports the trend rows for further analysis.

The self-contained HTML report keeps its theme, chart range, service, relationship, collapse, and per-section image controls without requiring the application to be running. Sections omitted by the Export Composer remain excluded from that offline report.

## 9. CSV Re-Import
The analytics page can rebuild its visuals from one or more previously exported CSVs from this tool. Multiple files are stitched into one analytics dataset, while their timestamp months remain available in the monthly trend views.

1.  Open `/summary`.
2.  Enter the primary and secondary label types represented by the CSV (for example, `BU` and `app`).
3.  Optionally enter a dataset name so the combined analysis can be reopened without re-uploading the files.
4.  Choose one or more CSVs generated by this application.
5.  Click **Import CSVs**.

You can also start this flow directly from the main extractor page:

1.  Use the **Upload Existing CSV** section.
2.  Select the primary and secondary analysis label types above the upload panel.
3.  Choose one or more CSVs generated by this application.
4.  Click **Upload CSVs**.
5.  The app will import the selected files and take you directly to `/summary`.

Notes:
-   Import expects the CSV schema generated by this tool and requires `Src <label type>` / `Dst <label type>` columns for both selected dimensions. Header matching is case-insensitive.
-   Exact duplicate rows found in different files are removed, and matching unique connections are deduplicated across files. If overlapping exports contain differing aggregate rows, their remaining flow totals stay additive because the CSV does not include per-flow event IDs that would make partial-overlap deduplication reliable. Non-overlapping export windows are still recommended.
-   Selecting the same file content twice is rejected. Up to 60 CSVs can be selected within the combined 64 MiB upload limit.
-   The coverage panel shows the date span, covered months, missing months, and overlapping source windows. Missing months appear as gaps in line charts rather than as zero traffic.
-   Named dataset collections persist locally in the current user's owner-readable application configuration. They contain derived analytics and report metadata, not PCE credentials or copies of the source CSV files.
-   This is useful if the app was restarted or the original in-memory analytics state is no longer present.
-   After import, `/summary` now forces a fresh analytics reload so the imported dataset appears immediately instead of reusing an older empty-state response.

## 10. Templates, Scheduling, and Delivery

Open `/automation` or click **Templates & Automation** on the extractor page.

### Create a template

1.  Select a saved PCE profile. A new template can copy that profile's current filters and analytics dimensions as a starting point.
2.  Enter the template name, filters, rolling number of trailing days, chunk interval, and an absolute output folder.
3.  Use a filename pattern. The recommended default is `blocked-{template}-{date}-{time}.csv`; supported tokens are `{template}`, `{date}`, `{time}`, `{timestamp}`, and `{run_id}`.
4.  Set the number of local artifacts to retain. Retention only removes paths previously recorded as successful artifacts for this template.
5.  Select whether the run should also generate self-contained HTML and PDF executive reports, then set their optional title, customer, prepared-by, and notes fields.
6.  Save the template, then use **Queue Manual Run** to verify it. Manual delivery is disabled unless selected in the alert policy.

Templates can be duplicated or exported as JSON. Imported/exported templates contain no PCE credentials, delivery credentials, IDs, or scheduler state. A template cannot be saved without an existing PCE profile, and a profile or delivery destination cannot be deleted while a template references it.

### Configure a schedule

Available frequencies are daily, weekdays, weekly, monthly, and a standard five-field cron expression. Every schedule requires an IANA timezone such as `America/Chicago` or `UTC`.

-   **Run once after startup:** Queues one missed execution when the app was not running at the scheduled time.
-   **Skip missed run:** Advances directly to the next future occurrence.
-   **Queue another:** Preserves every due execution in the single-worker queue.
-   **Skip overlap:** Does not add another job while that template is queued or running.

Schedules run only while the application process is running. Queued jobs persist across restarts; an interrupted running job is marked failed rather than silently retried.

### Configure delivery destinations

-   **Generic Webhook:** Sends summary JSON, JSON with a base64 artifact, or multipart metadata plus an artifact file. Inline base64 is limited to 4 MiB; use multipart for larger reports. HTTPS is required unless private-network access is explicitly enabled.
-   **Slack Webhook:** Sends a formatted notification to the webhook's configured channel. Incoming webhooks do not upload files.
-   **Slack App:** Requires a bot token with `files:write` and a channel ID. The app must be a member of the destination channel. CSV delivery uses Slack's external upload URL and completion APIs.
-   **Teams Workflow:** Posts an Adaptive Card to a `When a Teams webhook request is received` URL. In base64 mode, `file_name`, `file_base64`, and `file_sha256` are added to the request so the Power Automate workflow can validate and create the CSV in SharePoint or OneDrive. Inline files are limited to 4 MiB.
-   **Email / SMTP:** Sends generated artifacts as MIME attachments. TLS can use implicit TLS on port 465 or STARTTLS on other ports such as 587. Authenticated SMTP requires TLS; TLS may be disabled only for an unauthenticated local relay.
-   **Shared Folder:** Copies generated artifacts to an absolute local, mounted, or network-share path without overwriting an existing file.
-   **SFTP:** Uploads generated artifacts using a password or absolute private-key path. The server's public host key is mandatory and pinned; insecure host-key bypass is not supported.

When HTML or PDF generation is enabled, each successful delivery destination receives the CSV and each selected executive artifact. Run history provides a separate download link for every retained format.

Use **Test Saved Destination** before associating a destination with a template. Webhook URLs, tokens, header values, SMTP passwords, and SFTP passwords are stored only in the owner-readable local automation store and are not returned to the browser.

Exported template files omit destination associations. Imported templates keep their query and schedule settings but start with scheduling disabled, so you can select local profiles and destinations and review them before activation.

### Configure alert conditions

Delivery can occur after every successful run, only when the report changes, or when thresholds match. Conditions include:

-   Minimum blocked flow count
-   Absolute run-to-run flow percentage change
-   Newly observed primary-dimension relationships
-   Newly observed protocol/port pairs
-   External/unmanaged traffic
-   Extraction failures

The first successful run has no baseline and is eligible for delivery. Run history records why delivery was skipped or the result for every attempted destination.

### Headless and start-at-login operation

Run one template and exit:

```bash
./IllumioTrafficTool_Linux --run-template "Weekly Report"
```

Run the scheduler without the local web server:

```bash
./IllumioTrafficTool_Linux --scheduler-only --open-browser=false
```

Only one application process can use the current user's stores. For normal start-at-login use, the installers run the full application with browser opening disabled, leaving both scheduling and `http://localhost:8080` available:

```bash
./scripts/install_scheduler_linux.sh /absolute/path/IllumioTrafficTool_Linux
./scripts/install_scheduler_macos.sh /absolute/path/IllumioTrafficTool_MacOS_AppleSilicon
```

On Windows, run PowerShell as the intended desktop user:

```powershell
.\scripts\install_scheduler_windows.ps1 -BinaryPath C:\Tools\IllumioTrafficTool_Windows.exe
```

Pass `--uninstall` to the Linux/macOS scripts or `-Uninstall` to the Windows script to remove the startup integration.

## 11. Validation and Smoke Testing
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

## 12. Troubleshooting
-   **HTTP 401/403:** Your API Key or Secret is incorrect, or the user does not have permission to run traffic queries.
-   **HTTP 404:** The PCE URL or Org ID is incorrect.
-   **Connection Refused:** Ensure your machine has network access to the PCE URL provided.
-   **Remote Users Cannot Reach the App:** This is intentional. The current release is local-only and has no remote hosting mode.
-   **0 Flows Found:** Verify your label names. Labels must match the exact case and spelling used in the PCE.
-   **Heatmap looks too large:** Use the source and destination filters or leave `Hide Empty Rows/Cols` enabled.
-   **Live smoke test cannot connect:** Ensure the local machine has network access to the PCE and that the selected saved profile is still valid.
-   **A second copy will not start:** The application intentionally permits one process per local user. Stop the existing UI or scheduler process before using `--run-template` or `--scheduler-only` separately.
-   **Scheduled run was not delivered:** Review `/automation` run history. It records threshold skips and per-destination delivery failures without exposing secrets.
-   **Webhook rejected as private:** Use HTTPS for public services. Enable private-network access only for an intentional internal webhook target.
-   **Slack notification arrived without a CSV:** Slack incoming webhooks are notification-only. Configure the Slack App destination for file upload.
-   **Teams card arrived without a CSV:** Configure base64 mode and add Power Automate actions that decode `file_base64` and create `file_name` in SharePoint or OneDrive.
