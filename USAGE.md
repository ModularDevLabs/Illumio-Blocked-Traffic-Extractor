# User Guide: Illumio Blocked Traffic Extractor

## 1. Getting Started
1.  Launch the executable (`IllumioTrafficTool_Linux`, `.exe`, or `_MacOS`).
2.  By default, your browser will automatically open to `http://localhost:8080`.
3.  Ensure the tool remains running in the background while you use the web interface.

## 2. Hosting Options
The tool can run either as a local desktop app or as a centrally hosted web app.

-   **Local desktop mode:** Run the binary with no arguments. It binds to `127.0.0.1:8080` and opens a browser automatically.
-   **Central server mode:** Bind to a server interface and choose a port so other users can browse to it by IP or DNS name.

Examples:

```bash
./IllumioTrafficTool_Linux -host 0.0.0.0 -port 9090 -open-browser=false
```

```bash
ITT_HOST=0.0.0.0 ITT_PORT=9090 ITT_OPEN_BROWSER=false ./IllumioTrafficTool_Linux
```

Notes:
-   Use `-host 0.0.0.0` to listen on all IPv4 interfaces.
-   Use `-port <number>` to choose the hosted port.
-   Use `-open-browser=false` for server deployments.
-   After startup, users can browse to `http://<server-ip-or-dns>:<port>`.

## 3. Managing PCE Profiles
The tool allows you to save credentials for multiple Illumio environments.
-   **To Save a Profile:** Enter your PCE URL, Org ID, API Key, and Secret. Enter a name in the "New Profile Name" field and click **Save Current Config**.
-   **To Load a Profile:** Select the desired PCE from the dropdown menu.
-   **To Delete a Profile:** Select the profile from the dropdown and click **Delete**.

## 4. Running an Extraction
1.  **Select/Enter Credentials:** Ensure the PCE details are correct.
2.  **Define Filters:**
    -   **Sources/Destinations:** Enter label names (e.g., `App: DB`) or IP addresses. Separate multiple items with commas.
    -   **Services:** Enter specific service names to filter by (e.g., `SSH, MySQL`). Leave empty to pull all services.
    - **Exclusions:** Enter labels or IPs you wish to exclude from either the Source or Destination side.
    - **Days To Fetch:** Choose how many days of blocked traffic to query. The default is 90.
3.  **Configure Export:**
    -   **Target Filename:** Choose a name for your CSV (e.g., `march_report.csv`).
    -   **Target Folder:** Enter the **absolute path** to the folder where the file should be saved (e.g., `C:\Users\Admin\Desktop` or `/home/user/Downloads`).
4.  **Start:** Click **Start Fetch**.

## 5. Monitoring & Controls
-   **Progress Bar:** Shows the percentage of the 90-day window completed.
-   **Status Label:** Displays how many days have been processed and the total flow count gathered so far.
-   **Log Box:** Provides a detailed, real-time feed of API interactions and errors.
-   **Cancel Button:** Use this to stop the extraction immediately. **Note:** If you cancel, the partial data will not be saved to ensure CSV integrity.

## 6. Troubleshooting
-   **HTTP 401/403:** Your API Key or Secret is incorrect, or the user does not have permission to run traffic queries.
-   **HTTP 404:** The PCE URL or Org ID is incorrect.
-   **Connection Refused:** Ensure your machine has network access to the PCE URL provided.
-   **Remote Users Cannot Reach the App:** Ensure you started the tool with `-host 0.0.0.0` or another reachable interface, and that the server firewall/security group allows the selected port.
-   **0 Flows Found:** Verify your label names. Labels must match the exact case and spelling used in the PCE.
