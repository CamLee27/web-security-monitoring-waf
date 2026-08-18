# Detection and Classification

## Goal

The monitoring layer identifies and records security-relevant HTTP activity without treating every unusual request as malicious.

Classification is heuristic and intentionally conservative.

## Security Requests Recorded

The Worker records selected server-side requests including:

- HTTP 404 responses
- Requests matching suspicious-path patterns

It intentionally avoids recording every static asset request.

## Suspicious-Path Examples

```text
/.env
/.env.production
/.git/config
/wp-admin
/wp-login.php
/wp-config.php
/xmlrpc.php
/phpmyadmin
/admin
/server-status
/cgi-bin/
/vendor/phpunit/
/actuator
/.aws/credentials
/.ssh/
/id_rsa
/config.php
/database.sql
/composer.json
/package.json
```

## Classification Labels

The current classifications are exactly:

```text
Likely Human
Uncertain
Likely Bot / Scanner
```

Confidence may be:

```text
Low
Medium
High
```

## Evidence Used

Classification can combine multiple signals, including:

- Cloudflare bot score, when available
- Cloudflare JavaScript detection status, when available
- Explicit bot/scanner user-agent patterns
- Suspicious paths
- Number of suspicious paths
- Repeated 404s
- Rapid request bursts
- Lack of intentional navigation
- Unusual or unrecognized browser information
- Hosting/cloud/VPN/proxy-associated network information
- Normal page-view behavior
- Intentional navigation behavior

## Conservative Classification

One weak signal should not automatically result in a bot/scanner classification.

`Likely Bot / Scanner` does **not** automatically mean malicious.

Classification and WAF blocking are separate decisions.

## Reported Client Information

For suspicious visitors, browser and device fields should be described as **reported** information because user-agent strings and browser hints can be spoofed.

## Real-World Traffic

The production CamCareer domain has received real automated scanning traffic.

Observed probe categories have included:

- WordPress files and directories
- Random PHP files
- Environment files
- Git metadata
- SSH/private-key paths
- Cloud/service-account configuration
- GraphQL endpoints
- Framework/development files

Do not publish real source IP addresses associated with this activity.
