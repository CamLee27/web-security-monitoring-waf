# Screenshot Plan

Do not upload unsanitized production screenshots.

## Recommended Screenshots

### `security-analytics.png`

Show Cloudflare Security Analytics and scanner-style request paths.

Redact source IP addresses, account/zone identifiers, location/network information, and private request metadata.

### `blocked-request.png`

Show a Cloudflare blocked page for a test path such as `/wp-admin`, `/.env`, or `/config.php`.

### `waf-rule.png`

Show custom WAF rule logic, rule name, and action.

Redact account ID, zone ID, and any sensitive internal notes.

### `d1-security-logs.png`

Show `request_observations` or sanitized example rows.

Redact IP, city, region, postal code, ISP/network organization, visitor hashes when appropriate, and identifying user-agent information.

### `security-email-report.png`

Show the report layout, classifications, totals, and security summary.

Redact personal email addresses, visitor IPs, visitor locations, network information, and identifying referrer data.

## Never Expose

```text
ADMIN_TOKEN
RESEND_API_KEY
REPORT_TO_EMAIL
personal email address
real visitor IP
real visitor location
real visitor ISP/network
Cloudflare account ID
Cloudflare zone ID
AWS secret
```
