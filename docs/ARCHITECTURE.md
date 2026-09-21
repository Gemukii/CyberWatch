# CyberWatch Architecture

CyberWatch is organized as a processing pipeline. Articles move through several specialized modules before being selected, summarized and published to Discord.

## Overview

```mermaid
flowchart LR
    CONFIG["config.py"]
    SOURCES["sources.py"]
    COLLECTOR["collector.py"]
    FILTERS["filters.py"]
    CATEGORIES["categories.py"]
    ENRICHMENT["enrichment.py"]
    CVE["cve_service.py"]
    SELECTION["selection.py"]
    SUMMARIZER["summarizer.py"]
    PUBLISHER["publisher.py"]
    STATE["state.py"]
    FEEDBACK["feedback.py"]
    BOT["bot.py"]
    DISCORD["Discord"]

    CONFIG --> BOT
    SOURCES --> COLLECTOR
    BOT --> COLLECTOR
    COLLECTOR --> FILTERS
    FILTERS --> CATEGORIES
    CATEGORIES --> ENRICHMENT
    ENRICHMENT --> CVE
    CVE --> SELECTION
    SELECTION --> SUMMARIZER
    SUMMARIZER --> PUBLISHER
    PUBLISHER --> DISCORD
    PUBLISHER --> STATE
    DISCORD --> FEEDBACK
```

## Components

CyberWatch separates the main processing pipeline from supporting services.

### Core pipeline

| Component       | Role                                                  |
| --------------- | ----------------------------------------------------- |
| `bot.py`        | Runs the Discord bot and orchestrates the application |
| `sources.py`    | Loads and manages configured RSS sources              |
| `collector.py`  | Fetches and normalizes articles                       |
| `filters.py`    | Removes irrelevant or invalid articles                |
| `categories.py` | Assigns article categories                            |
| `enrichment.py` | Adds additional information to articles               |
| `selection.py`  | Selects articles for publication                      |
| `summarizer.py` | Generates publication summaries                       |
| `publisher.py`  | Creates and sends Discord messages                    |

### Supporting services

| Component        | Role                                                |
| ---------------- | --------------------------------------------------- |
| `config.py`      | Loads application configuration                     |
| `cve_service.py` | Handles CVE-related information                     |
| `state.py`       | Maintains publication state and prevents duplicates |
| `feedback.py`    | Handles user feedback                               |

## Article processing

The main processing flow is:

```mermaid
sequenceDiagram
    participant B as Bot
    participant C as Collector
    participant F as Filters
    participant CA as Categories
    participant E as Enrichment
    participant S as Selection
    participant SU as Summarizer
    participant P as Publisher

    B->>C: Fetch configured feeds
    C-->>B: Normalized articles

    loop Each article
        B->>F: Validate and filter
        F-->>B: Accepted / rejected

        alt Article accepted
            B->>CA: Categorize
            CA-->>B: Category

            B->>E: Enrich
            E-->>B: Enriched article

            B->>S: Evaluate article
            S-->>B: Selected / rejected

            alt Article selected
                B->>SU: Generate summary
                SU-->>B: Summary
                B->>P: Publish
            end
        end
    end
```

## Publication state

Publication state is handled separately from the article processing pipeline.

Its purpose is to prevent an article from being repeatedly published while keeping publication state consistent with the actual Discord result.

```mermaid
sequenceDiagram
    participant P as Publisher
    participant D as Discord
    participant S as State

    P->>D: Send article

    alt Publication succeeds
        D-->>P: Success
        P->>S: Record publication
    else Publication fails
        D-->>P: Error
        P-->>P: Do not record publication
    end
```

This means a failed Discord publication does not permanently mark the article as published.

## Feedback

User feedback is handled after publication.

```mermaid
flowchart LR
    DISCORD["Published article"]
    --> USER["Discord user"]
    --> FEEDBACK["feedback.py"]
```

Feedback is kept separate from the article processing stages so that user interaction does not directly alter the collection pipeline.

## Configuration

Runtime configuration is handled by `config.py`.

RSS sources are maintained separately in:

```text
feeds.yaml
```

This keeps source configuration out of the application logic and allows feeds to be modified without changing the processing modules.

## Tests

Tests are located in:

```text
tests/
├── test_categories.py
├── test_filters.py
└── test_state.py
```

They focus on core processing behavior and state management.

## Deployment

CyberWatch supports containerized deployment through:

```text
Dockerfile
docker-compose.yml
```

The repository also contains a systemd service definition:

```text
cyberwatch.service
```

Automated tests are defined in:

```text
.github/workflows/tests.yml
```

The architecture intentionally keeps each processing step isolated so that individual parts can be tested and modified without having to change the entire pipeline.
