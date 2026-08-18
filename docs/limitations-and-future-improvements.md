# Limitations and Future Improvements

## Current Limitations

### Heuristic Classification

The system estimates whether activity appears human, uncertain, or bot/scanner-like.

These classifications are not definitive identity or intent determinations.

### Client Information Can Be Spoofed

User-agent strings, browser hints, platform hints, and device hints are client-reported information.

### Cloudflare Signals May Not Always Be Available

Bot score and JavaScript detection information are used when available.

### WAF and Worker Are Separate Layers

Cloudflare WAF custom rules handle blocking, while the Worker provides monitoring, classification, logging, and reporting.

### Integrated Production Worker

The security system is part of the same production Worker used by the visitor-reporting system.

This repository documents the security-focused implementation rather than representing a second independently deployed Worker.

### Public Repository Privacy

Production data contains visitor/security information that should not be published directly.

## Future Improvements

Potential improvements include:

- More structured suspicious-path categories
- Additional reporting around repeated scanner patterns
- Formal test cases for classification rules
- Regression tests for suspicious and normal paths
- Version-controlled sanitized WAF examples
- Long-term D1 trend analysis
- Sanitized aggregate security dashboards
- Retention-policy documentation
- Further internal separation of monitoring, classification, reporting, and mitigation logic
- Automated checks for accidentally committed secrets

## Safety and Privacy

Never commit:

```text
ADMIN_TOKEN
RESEND_API_KEY
REPORT_TO_EMAIL
real visitor IP addresses
real visitor location or postal information
real visitor ISP/network information
Cloudflare account IDs
Cloudflare zone IDs
AWS credentials
```
