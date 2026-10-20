# RPKI-PathWatch — AIORI Hackathon 3

**Team Code:** `A3-PS032-TC538`  
**Problem Statement:** PS-032 — Path and Reachability Analysis During RPKI State Changes  
**Problem Area:** Internet Measurements  
**Institution:** National Forensic Science University (NFSU), Guwahati Campus  
**Project Status:** Working MVP — historical RPKI state correlation pending

## Overview

RPKI-PathWatch is an Internet measurement prototype for analyzing Border Gateway Protocol (BGP) route observations, announcements, withdrawals, and AS-path changes in the context of Resource Public Key Infrastructure (RPKI) validation.

The current MVP collects and analyzes historical BGP data from RIPE Stat. It provides route snapshot comparisons, BGP update summaries, preliminary route-event reconstruction, and a Streamlit dashboard for reviewing the results.

The longer-term objective is to correlate historical RPKI validation-state transitions with changes in BGP paths and prefix visibility across routing collectors.

**Important:** Historical RPKI validation-state correlation has not yet been implemented. The current analysis does not establish that an RPKI state transition caused any observed BGP event or reachability change.

## Current MVP Features

- Retrieval of historical BGP route-state snapshots through RIPE Stat.
- Retrieval and normalization of historical BGP update events.
- Basic event classification into announcements and withdrawals.
- AS-path statistics and route snapshot comparisons.
- Preliminary reconstruction of route events and observed path changes.
- Streamlit dashboard for displaying analysis results.
- Raw data, processed data, and analysis outputs included for reproducibility.

### Current Dataset

The collected BGP update dataset covers **20–23 December 2024**, for the prefix `193.0.0.0/21`.

| Metric | Observed result |
|---|---:|
| BGP update events returned by the query | 266 |
| Announcements | 262 |
| Withdrawals | 4 |
| Distinct source IDs | 42 |
| Events containing an AS path | 262 |
| Observed path changes reported by the preliminary reconstruction | 112 |
| Announcements after withdrawals reported by the preliminary reconstruction | 3 |

These counts describe the collected query results, not all global BGP activity. The path-reconstruction metrics are preliminary and require further validation before being treated as definitive findings.

## Data Sources

- **RIPE Stat:** Historical BGP route-state and BGP update observations.
- **Current RPKI validation lookup:** Stored separately from the historical BGP observations.

The current RPKI lookup is not a historical record of the validation state at the time of the collected BGP events. It must not be used as a substitute for historical RPKI state-transition data.

## Repository Structure

```text
A3-PS032-TC538/
├── .gitignore
├── README.md
├── Proposed-structure-hackathon.pdf
├── RPKI-PathWatch-AIORI-Hackathon3.pdf
├── app.py
├── requirements.txt
├── data/
│   ├── raw/
│   │   ├── historical BGP route snapshots
│   │   ├── historical BGP update events
│   │   ├── collection manifests
│   │   └── current RPKI lookup
│   └── processed/
│       ├── normalized route snapshots
│       ├── route analysis summaries
│       ├── BGP update summaries
│       ├── snapshot comparisons
│       └── route event reconstruction
└── src/
    ├── README.md
    ├── ingest.py
    ├── normalize.py
    ├── analyze.py
    ├── fetch_updates.py
    ├── analyze_updates.py
    ├── compare.py
    └── reconstruct_routes.py
```

## Run the MVP Locally

### Requirements

- Python 3.10 or newer recommended
- Git
- Internet access for retrieving new data through the ingestion scripts

### Installation

Clone the repository and enter its directory:

```bash
git clone https://github.com/Akshat1806/A3-PS032-TC538.git
cd A3-PS032-TC538
```

Create and activate a virtual environment if desired, then install dependencies:

```bash
python -m venv .venv
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the requirements:

```bash
pip install -r requirements.txt
```

### Launch the Dashboard

```bash
python -m streamlit run app.py
```

Streamlit will provide a local URL, normally `http://localhost:8501`.

The dashboard reads the analysis files under `data/processed/`. Keep the existing repository data files in place when running the included demonstration.

## Source Code and Deliverables

- **[Repository home](https://github.com/Akshat1806/A3-PS032-TC538)**
- **[Source scripts](https://github.com/Akshat1806/A3-PS032-TC538/tree/main/src)**
- **[Streamlit dashboard source](https://github.com/Akshat1806/A3-PS032-TC538/blob/main/app.py)**
- **[Dependencies](https://github.com/Akshat1806/A3-PS032-TC538/blob/main/requirements.txt)**
- **[Raw collected data](https://github.com/Akshat1806/A3-PS032-TC538/tree/main/data/raw)**
- **[Processed data and analysis results](https://github.com/Akshat1806/A3-PS032-TC538/tree/main/data/processed)**
- **[Final presentation PDF](https://github.com/Akshat1806/A3-PS032-TC538/blob/main/RPKI-PathWatch-AIORI-Hackathon3.pdf)**
- **[Official presentation structure PDF](https://github.com/Akshat1806/A3-PS032-TC538/blob/main/Proposed-structure-hackathon.pdf)**

## Team and Responsibilities

| Team member | Area of responsibility |
|---|---|
| Akshat | System architecture, data processing, event analysis, routing metrics, and dashboard integration |
| Krishn | Cybersecurity research, RPKI/BGP security, RFC review, test scenarios, and validation |
| Parthajit Borah | Research guidance, methodology review, technical feedback, and interpretation |

## Known Limitations

- Historical RPKI validation-state transitions have not yet been integrated into the analysis.
- The current RPKI lookup does not establish historical validation states.
- The current dataset covers a selected prefix and a limited time window.
- RIPE Stat query results do not necessarily represent every BGP event observed globally.
- Route-event reconstruction is preliminary and requires additional testing.
- A missing route observation at a collector does not, by itself, prove global prefix unreachability.
- Temporal correlation alone would not establish causation.

## Planned Work

The next development phase will focus on:

1. Obtaining suitable historical RPKI validation-state observations or VRP snapshots.
2. Detecting and timestamping RPKI validation-state transitions.
3. Correlating transitions with BGP announcements, withdrawals, AS-path changes, and prefix visibility.
4. Validating the event reconstruction logic and adding automated tests.
5. Evaluating observations across multiple collectors where data is available.
6. Improving dashboard visualizations and documenting reproducible evaluation scenarios.

These are planned capabilities and should not be interpreted as features already implemented in the current MVP.

## Team Introduction Video

**Status:** Uploaded.

**YouTube link:** [Proposed Solution](https://youtu.be/McxvNZqBUgg).

## References and Resources

- [RIPE Routing Information Service (RIS)](https://ris.ripe.net/)
- [RIPE Stat](https://stat.ripe.net/)
- [RouteViews](https://www.routeviews.org/)
- [NIST RPKI Monitor](https://rpki-monitor.antd.nist.gov/)
- [IETF RFC Editor](https://www.rfc-editor.org/)
- [RIPE NCC](https://www.ripe.net/)

---

Prepared for **AIORI Hackathon 3**  
Team: `A3-PS032-TC538`

## Current Prototype: Observation Limits

The current prototype processes a RIPE Stat BGP update sample and reconstructs
observed route-event sequences. The current analysis covers 266 events for the
selected prefix and observation window. It does not yet implement historical,
time-aligned RPKI validation-state correlation.

Interpret results within the following limits:

- **Collector coverage:** The dataset contains observations returned by the
  selected data source. It does not represent every network or routing
  collector on the Internet.
- **Withdrawals and reachability:** A withdrawal observed at one source does
  not establish that the prefix became globally unreachable. Missing route
  observations can also reflect measurement coverage or incomplete data.
- **Announcements after withdrawals:** These indicate a temporal sequence in
  the observed event stream. They do not, by themselves, prove end-to-end
  recovery or restored service.
- **AS-path changes:** A changed observed AS path is a routing observation.
  It does not establish that an RPKI state change caused the change.
- **Historical RPKI state:** Current RPKI validation status must not be treated
  as the historical status at the time of a past BGP event. Historical
  correlation requires validation data aligned with the event timestamps.
- **Missing or malformed paths:** An absent or invalid AS path limits what can
  be inferred from that event. It must not be interpreted as proof that no
  route existed in reality.
- **Event-window boundaries:** A withdrawal without a previously tracked route
  means no active route was tracked for that prefix/source pair in the
  processed event history. It does not prove that no route existed before the
  observation window or elsewhere.

The current event reconstruction therefore describes observed BGP event
sequences, not proven global reachability outcomes or causal effects of RPKI
state changes. Historical RPKI correlation and broader reachability analysis
remain future evaluation tasks.