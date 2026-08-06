# Release Notes — v1.4.0

## Templates and scheduled automation

- Added reusable report templates that reference saved PCE profiles without duplicating credentials.
- Added daily, weekday, weekly, monthly, and advanced cron schedules with explicit timezone, missed-run, and overlap policies.
- Added a persistent single-worker queue, restart recovery, manual queued runs, cancellation, run history, and headless `--run-template` execution.
- Added tokenized artifact filenames, non-overwriting delivery, per-template retention, and downloadable run artifacts.

## Delivery and alerting

- Added generic JSON, base64, and multipart webhook delivery. Inline base64 artifacts are capped at 4 MiB, while multipart delivery supports reports up to the 64 MiB delivery limit.
- Added Slack incoming-webhook notifications and Slack app CSV upload using the current external upload workflow.
- Added Teams Workflow Adaptive Cards with optional base64 artifact data for Power Automate file creation.
- Added SMTP email attachments, shared-folder delivery, and host-key-pinned SFTP delivery.
- Added destination tests, bounded retries, secret redaction, HTTPS and private-address protections, and persistent delivery results.
- Added conditional delivery for new relationships, new services, external traffic, minimum flow volume, and run-to-run percentage changes.
- Corrected analytics and executive-summary external-destination rankings so labeled managed destinations are never sourced from the general top-destination list.

## Operations

- Added the `/automation` workspace for templates, destinations, schedules, and run history.
- Added owner-only automation persistence and a cross-platform single-instance lock.
- Added Linux systemd user-service, Windows scheduled-task, and macOS LaunchAgent installers for start-at-login operation.
