# Cloudflare WAF Rules

## Purpose

Cloudflare WAF custom rules provide the mitigation layer for clearly inappropriate requests observed against the production CamCareer site.

> The WAF exists separately from the Cloudflare Worker. The Worker provides monitoring/detection; the WAF provides blocking.

## Rule 1: WordPress Scanner Paths

Examples:

```text
/wp-admin
/wp-login.php
/wp-config.php
/wp-*
/xmlrpc.php
```

CamCareer does not use WordPress, so these requests are inappropriate for the site.

## Rule 2: Secret and Repository Probes

Examples:

```text
/.env
/.env.production
/.git/
/.git/config
/.aws/credentials
/.ssh/
/id_rsa
```

These requests target files that should not be publicly exposed.

## Rule 3: PHP Scanner Probes

Examples:

```text
/config.php
/wp-login.php
/random-file.php
```

CamCareer is a static site and does not depend on PHP, so `.php` requests can be blocked for this deployment.

## Verified Behavior

Live testing confirmed:

- `/wp-admin` blocked by Cloudflare
- `/.env` blocked by Cloudflare
- `/config.php` blocked by Cloudflare
- Normal site remained accessible after WAF deployment

## Design Decision: No Arbitrary Aggressive Rate Limit

The mitigation strategy was informed by observed production scanner behavior rather than immediately applying an aggressive global rate limit.

Rate-based classification/reporting signals and WAF blocking thresholds remain separate concepts.

## Evidence Source

Cloudflare Security Analytics was reviewed to identify real scanner patterns reaching the production domain.

Public screenshots must sanitize:

- Source IPs
- Visitor location
- Network/ISP information
- Account identifiers
- Zone identifiers
- Any other private request metadata
