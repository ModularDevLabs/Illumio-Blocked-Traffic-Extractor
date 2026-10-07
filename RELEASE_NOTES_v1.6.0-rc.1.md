# v1.6.0-rc.1 Traffic Extraction and Large CSV Imports

This testing prerelease brings the traffic extraction improvements from the combined dashboard into the standalone application, including large CSV imports. It remains localhost-only and does not replace stable v1.5.0.

## Traffic extraction

- Choose blocked-only or all-traffic extraction. Blocked-only remains the default, while all-traffic exports retain policy decisions for analysis and re-import.
- Exclude PCE service objects or explicit protocol and port selectors in manual runs, saved profiles, and report templates.
- Traffic downloads stream without the previous 256 MiB total-response cutoff. Progress logs show downloaded bytes and decoded rows, and PCE-reported row truncation triggers smaller query windows while preserving filters.
- Failed query windows no longer discard completed windows or stop the remaining chunks. Cancellation and overall timeouts also preserve completed data in marked partial CSVs, with coverage manifests identifying missing windows.
- Partial scheduled runs retain downloadable artifacts without being treated as successful reports or comparison baselines. CSVs are also retained if subsequent report generation fails.

## CSV imports

- Removed the 64 MiB combined upload cap. There is no fixed per-file or total CSV upload-size limit.
- Larger uploads use the system temporary folder after an 8 MiB file-memory budget, and raw CSV rows are parsed incrementally to reduce peak memory use.
- CSV imports are exempt from the web server's fixed upload and response deadlines, so a slow upload or long analysis can finish. Other routes retain their existing protections.
- Both import screens show file count, total size, upload progress, and the analysis phase. Connection failures, unreadable responses, storage failures, and invalid CSV rows produce clearer errors.
- Duplicate concurrent imports are prevented, temporary uploads are cleaned up, and failed imports leave the previous analytics intact.
- Cross-file exact-row deduplication, unique connections, and monthly statistics retain their existing meaning.

Available RAM and temporary disk space still limit practical dataset size; derived analytics remain in memory. The 60-file batch limit remains. PCE limits, query deadlines, and metadata-response safety bounds still apply. No CSV can be recovered if no query window completed or storage cannot be written.

## Release artifacts

- `IllumioTrafficTool_v1.6.0-rc.1_Linux`
- `IllumioTrafficTool_v1.6.0-rc.1_Windows.exe`
- `IllumioTrafficTool_v1.6.0-rc.1_MacOS_Intel`
- `IllumioTrafficTool_v1.6.0-rc.1_MacOS_AppleSilicon`

Executable filenames and the page footer identify this release candidate. Builds use the patched Go 1.26.8 toolchain and updated SSH/SFTP dependency security fixes.
