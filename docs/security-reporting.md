# Security Reporting

## Overview

Security reporting uses permanent Cloudflare D1 history together with report cursors.

The report system does not delete the underlying security rows after an email is sent.

## Relevant D1 Tables

### `request_observations`

Stores permanent server-side request/security history.

Recorded fields include information such as:

- Visitor hash
- IP address
- Date
- Timestamp
- Path
- HTTP method
- Status
- 404 indicator
- Suspicious-path indicator
- Suspicious categories
- Referrer
- Approximate location fields
- Network/ISP organization
- User agent
- Browser client hints
- Platform hint
- Mobile hint
- Cloudflare bot score, when available
- Cloudflare JavaScript detection status, when available

### `report_state`

Known columns include:

```text
last_reported_request_id
last_reported_page_view_id
last_reported_navigation_id
updated_at
```

## Cursor-Based Design

```text
D1 stores permanent rows
        ↓
Report reads rows newer than the saved cursor
        ↓
Email is submitted to Resend
        ↓
Resend successfully accepts the email
        ↓
Report cursor advances
        ↓
Original D1 rows remain stored
```

## Reporting Schedule

```text
0 */4 * * *
```

## Manual Reporting

Endpoint:

```text
/__visitor-report-test
```

Method:

```text
POST
```

Required header name:

```text
x-admin-token
```

The Worker compares the supplied value against:

```text
ADMIN_TOKEN
```

The actual token must never be stored in this repository.

## Report Totals

The current report includes totals such as:

- Unique visitors
- Likely Humans
- Uncertain
- Likely Bots / Scanners
- Recorded page views
- Intentional navigation clicks
- Suspicious requests
- Recorded security-relevant requests

## Secrets and Private Data

Never publish:

```text
ADMIN_TOKEN
RESEND_API_KEY
REPORT_TO_EMAIL
real visitor IP addresses
real visitor location data
real visitor ISP/network data
Cloudflare account identifiers
Cloudflare zone identifiers
AWS credentials or secrets
```

## Email Success and Cursor Advancement

Do not advance the report cursor until Resend has successfully accepted the email.
