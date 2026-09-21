## 2. CVE intelligence

### Motivation

The existing enrichment pipeline uses CVE information to improve article ranking and detect exploitation signals.

This is useful for automated monitoring, but it does not provide a way for a user to directly investigate a vulnerability from Discord.

Version 1.2 introduces `/cyber-cve` to expose this information directly.

The feature intentionally reuses the existing KEV and EPSS infrastructure instead of creating a second implementation of those clients.

### Responsibilities

The CVE lookup is split into separate responsibilities:

```text
Discord command
      │
      ▼
    bot.py
      │
      ▼
cve_service.py
   ┌──┼───────────────┐
   ▼  ▼               ▼
 NVD KEV/EPSS      state.py
   │  │               │
   └──┴───────┬───────┘
               ▼
         CVE information
               │
               ▼
          publisher.py
               │
               ▼
            Discord
```

### `CVEInfo`

`CVEInfo` is the internal representation of a vulnerability.

It separates vulnerability data from article data and allows the same CVE information to be used by Discord commands and future monitoring features.

The model contains only structured vulnerability information, such as:

* CVE identifier
* description
* CVSS information
* EPSS information
* CISA KEV status
* ransomware information when available
* references
* publication metadata

### `cve_service.py`

`cve_service.py` is the orchestration layer for CVE lookups.

The Discord bot does not directly communicate with the individual vulnerability APIs.

This keeps:

* API handling out of `bot.py`
* external data sources replaceable
* error handling centralized
* the feature independently testable

### NVD

NVD provides the general CVE information required by `/cyber-cve`, including vulnerability descriptions, CVSS information and references.

KEV and EPSS are intentionally not treated as replacements for NVD.

They answer different questions:

* NVD: what is the vulnerability?
* KEV: is it known to be exploited?
* EPSS: how likely is exploitation according to the EPSS model?

### KEV and EPSS reuse

CyberWatch already retrieves CISA KEV and FIRST EPSS data during article enrichment.

Version 1.2 reuses these existing clients instead of duplicating their implementation.

This keeps the automated watch pipeline and interactive CVE lookup based on the same security signals.

### CyberWatch history

`state.py` already maintains the information required to prevent duplicate publications and track published CVEs.

Version 1.2 exposes this information through the CVE service.

For a requested CVE, CyberWatch can therefore distinguish:

```text
External vulnerability intelligence
        +
CyberWatch publication history
```

This means `/cyber-cve` provides context specific to the bot rather than acting as a simple NVD wrapper.

### Error handling

External services are not assumed to be permanently available.

The CVE service must handle:

* invalid CVE identifiers
* CVEs not found
* API timeouts
* HTTP errors
* incomplete vulnerability data
* unavailable KEV or EPSS services

A failure of one enrichment source should not cause the Discord bot to crash.

### Why no database?

The CVE lookup does not introduce a new database.

CyberWatch already follows a disposable architecture where application state is reconstructed from Discord history.

Adding a database only for `/cyber-cve` would introduce another persistent component without being necessary for the feature.

The v1.2 implementation therefore keeps the same architecture.

### Future extension

This separation intentionally prepares the project for the v1.3 CVE watchlist.

A future watchlist can reuse:

```text
CVE service
    │
    ├── NVD
    ├── KEV
    ├── EPSS
    └── CyberWatch state
```

without modifying the existing article collection pipeline.
