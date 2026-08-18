# Workers KV to D1 Migration

## Original Design

The original implementation used Cloudflare Workers KV.

As security monitoring expanded, real-world scanner traffic produced a large number of request records.

At one observed point, KV usage was approximately:

```text
Read operations:   600
Write operations:  730
Delete operations: 220
List operations:    40
```

These were point-in-time values, not permanent usage figures.

## Problem

The KV model created increased write/delete pressure and did not fit the desired permanent security-event history.

## Current Design

Production storage was migrated to Cloudflare D1.

Database:

```text
camcareer-security-logs
```

Worker binding:

```text
SECURITY_DB
```

The old Worker binding:

```text
VISITOR_LOGS
```

has been removed.

## Architectural Change

### Previous

```text
Event
  ↓
KV
  ↓
Email report
  ↓
Record cleanup/deletion
```

### Current

```text
Event
  ↓
Permanent D1 row
  ↓
Report reads rows after cursor
  ↓
Email successfully accepted
  ↓
Cursor advances
  ↓
D1 row remains stored
```

## Current D1 Tables

```text
request_observations
page_view_observations
navigation_events
report_state
```

This security repository primarily focuses on:

```text
request_observations
report_state
```

## Old KV Namespace

The previous KV namespace may remain temporarily as an empty, disconnected rollback backup.

The intended verification is to let normal production Cron cycles run and then confirm the old KV namespace receives essentially no new reads, writes, deletes, or list operations.
