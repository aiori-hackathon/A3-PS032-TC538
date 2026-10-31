# RPKI-PathWatch — Deployment Guide

## 1. Overview

RPKI-PathWatch is a prototype for analyzing BGP routing events and their relationship with Resource Public Key Infrastructure (RPKI) validation states.

The deployed application uses Flask, Gunicorn, an HTML/JavaScript frontend, and RIPE RIS Live WebSocket monitoring.

Production URL: https://a3-ps032-tc538.onrender.com

Repository: https://github.com/aiori-hackathon/A3-PS032-TC538

Deployment branch: integration/flask-frontend

## 2. Architecture

```text
Browser
   |
   v
Render Web Service
   |
   v
Gunicorn
   |
   v
wsgi.py
   |
   v
app.py (Flask)
   |
   +------ Frontend (web/index.html)
   |
   +------ Historical Data APIs
   |
   +------ Live Monitor
              |
              v
        RIPE RIS Live WebSocket
              |
              v
        BGP UPDATE Processing
              |
              v
        Prefix Filtering
              |
              v
        RPKI Validation
              |
              v
        Bounded Event Buffer
```

## 3. Main Components

| File | Responsibility |
|---|---|
| app.py | Flask application and API routes |
| wsgi.py | Gunicorn entry point |
| web/index.html | Frontend dashboard |
| src/live_monitor.py | RIPE RIS Live monitoring |
| src/vrp_cache.py | Shared VRP cache |
| src/rpki_validator.py | RPKI validation |
| src/timestamp_policy.py | Timestamp policy |
| src/data_layer.py | Data access and processing |
| legacy/app_streamlit.py | Legacy Streamlit application |

## 4. Render Configuration

| Setting | Value |
|---|---|
| Service | A3-PS032-TC538 |
| Runtime | Python 3 |
| Region | Singapore |
| Instance | Free |
| Root directory | Repository root |
| Branch | integration/flask-frontend |

Build command:

```bash
pip install -r requirements.txt
```

Start command:

```bash
gunicorn --workers 1 --bind 0.0.0.0:$PORT wsgi:app
```

WSGI entry point:

```python
from app import app
```

## 5. Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| PATHWATCH_LIVE_PREFIX | Prefix monitored by RIS Live | 193.0.0.0/21 |

Configure this variable in Render Dashboard > Service > Environment.

Example:

```text
PATHWATCH_LIVE_PREFIX=193.0.0.0/21
```

A broader diagnostic test prefix was also used:

```text
PATHWATCH_LIVE_PREFIX=193.0.0.0/16
```

Restore the intended production prefix after testing.

## 6. API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| / | GET | Dashboard |
| /api/health | GET | Application health |
| /api/dashboard | GET | Historical dashboard data |
| /api/events | GET | Historical events |
| /api/events.csv | GET | Event export |
| /api/live/status | GET | Live monitor status |
| /api/live/events | GET | Buffered live events |
| /api/live/start | POST | Start live monitoring |
| /api/live/stop | POST | Stop live monitoring |

## 7. RIPE RIS Live Monitoring

WebSocket endpoint:

```text
wss://ris-live.ripe.net/v1/ws/?client=rpki-pathwatch-a3-ps032
```

The monitor sends a subscription with:

- type: UPDATE
- prefix: PATHWATCH_LIVE_PREFIX
- moreSpecific: true
- lessSpecific: false
- acknowledge: true

The monitor handles:

1. WebSocket connection.
2. Subscription acknowledgement.
3. Ping/pong messages.
4. RIS error messages.
5. BGP UPDATE messages.
6. Announcements and withdrawals.
7. Prefix filtering.
8. RPKI validation.
9. Bounded event buffering.

A successful connection and subscription acknowledgement do not prove that BGP updates have been received.

## 8. RPKI Validation Data

Live event validation uses the shared VRP cache.

The implementation includes local fallback data, a shared cache, refresh metadata, and last-known-good snapshot retention.

Important deployment limitation:

The VRP cache worker currently starts inside the direct execution block of app.py. Gunicorn imports the application through wsgi.py, so that block does not execute in the deployed configuration.

Production cache-worker lifecycle integration remains necessary.

The fallback VRP data must not be interpreted as historical validation data for older BGP events.

## 9. Render Free-Tier Limitations

- Services may sleep after inactivity.
- Cold starts can delay the first request.
- Filesystem storage is ephemeral.
- CPU and RAM are limited.
- The live event buffer is bounded to 1,000 events by default.
- Large VRP downloads require memory evaluation.
- The application currently uses one Gunicorn worker.

The single-worker configuration is important because the monitor and its event buffer are process-local.

Multiple workers would have separate monitor instances and event buffers.

## 10. Deployment Procedure

Deployment branch:

```text
integration/flask-frontend
```

Check branch:

```bash
git branch --show-current
```

Switch branch:

```bash
git checkout integration/flask-frontend
```

Check changes:

```bash
git status
```

Stage documentation:

```bash
git add README.md DEPLOYMENT.md
```

Commit:

```bash
git commit -m "Document Flask deployment and live monitoring"
```

Push:

```bash
git push origin integration/flask-frontend
```

Render automatically deploys changes from the configured deployment branch.

Do not merge into main without explicit team approval.

## 11. Post-Deployment Verification

Health:

https://a3-ps032-tc538.onrender.com/api/health

Dashboard:

https://a3-ps032-tc538.onrender.com/

Live dashboard:

https://a3-ps032-tc538.onrender.com/#view=live

Live status:

https://a3-ps032-tc538.onrender.com/api/live/status

Live events:

https://a3-ps032-tc538.onrender.com/api/live/events

Verify:

- Dashboard loads.
- Historical data is accessible.
- WebSocket connects.
- Subscription acknowledgement arrives.
- BGP updates are received.
- Events are processed.
- VRP validation data is appropriately refreshed.

## 12. Verified Deployment Milestones

| Milestone | Result |
|---|---|
| Render deployment | Successful |
| Gunicorn startup | Successful |
| Flask dashboard | HTTP 200 |
| Historical health endpoint | HTTP 200 |
| Historical BGP events | 266 |
| Processed files | 13 |
| RIPE RIS Live connection | Successful |
| Subscription acknowledgement | Successful |
| Actual live BGP ingestion | Not yet verified |
| Live event buffer population | Not yet verified |
| Periodic VRP refresh under Gunicorn | Not yet implemented |

These are observed test results, not a claim that every live capability is production-ready.

## 13. Remaining Development Tasks

### Live BGP ingestion
- Investigate incoming RIS message types.
- Verify actual UPDATE message receipt.
- Test prefix filtering.
- Test announcement and withdrawal processing.
- Add message-type counters and diagnostics.

### VRP cache lifecycle
- Integrate the refresh worker into production startup and shutdown.
- Prevent duplicate workers.
- Evaluate memory consumption.
- Preserve last-known-good data.
- Report validation data freshness accurately.

### Persistence
- Evaluate persistent storage for generated monitoring results.
- Avoid depending on ephemeral filesystem storage.

### Monitoring architecture
- Evaluate a separate background monitoring service.
- Consider shared event storage before introducing multiple web workers.

### Historical RPKI correlation
- Obtain historical VRP snapshots.
- Align validation-state transitions with BGP event timestamps.
- Analyze announcements, withdrawals, AS-path changes, and prefix visibility.
- Distinguish correlation from causation.

## 14. Current Project Status

RPKI-PathWatch has a deployed Flask dashboard with historical BGP analysis and an opt-in RIPE RIS Live monitoring component.

The initial deployment, historical data access, WebSocket connection, and subscription acknowledgement have been verified.

Actual live BGP ingestion and production VRP cache refresh remain under investigation.

Historical RPKI state-transition correlation remains planned work.

Production URL: https://a3-ps032-tc538.onrender.com

Deployment branch: integration/flask-frontend
