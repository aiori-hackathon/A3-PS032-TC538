"""PathWatch BGP & RPKI Historical Analysis Web Backend.

AIORI Hackathon 3, PS-032, Team A3-PS032-TC538.
Historical BGP/RPKI analysis dashboard for ONE study.
"""

from __future__ import annotations

import sys
from pathlib import Path
from flask import Flask, Response, jsonify, request, send_from_directory

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.live_monitor import monitor, load_local_vrps
from src.vrp_cache import vrp_cache
from src.data_layer import (
    PROCESSED_DIR,
    export_events_csv,
    filter_events,
    load_dataset,
    parse_event_filter_args,
)

app = Flask(__name__, static_folder="web", static_url_path="")

# Preserve existing local validation data until the first successful feed refresh.
_fallback_vrps, _fallback_source, _fallback_time = load_local_vrps()
vrp_cache.seed_if_empty(_fallback_vrps, _fallback_source, _fallback_time)


@app.errorhandler(400)
def bad_request(error):
    msg = getattr(error, "description", "Bad Request")
    return jsonify({"error": "Bad Request", "detail": msg, "status_code": 400}), 400


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not Found", "detail": "Resource not found", "status_code": 404}), 404


@app.errorhandler(405)
def method_not_allowed(error):
    msg = getattr(error, "description", "Method Not Allowed")
    return jsonify({"error": "Method Not Allowed", "detail": msg, "status_code": 405}), 405


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal Server Error", "detail": "An internal error occurred", "status_code": 500}), 500


@app.get("/")
def index():
    return send_from_directory(ROOT / "web", "index.html")


@app.get("/api/health")
def health():
    data_exists = PROCESSED_DIR.exists()
    file_count = len(list(PROCESSED_DIR.glob("*.json"))) if data_exists else 0
    status = "ok"
    events_count = None
    try:
        data = load_dataset()
        events_count = len(data.get("events", []))
    except Exception:
        app.logger.exception("Health check failed to load dataset")
        status = "degraded"

    return jsonify({
        "status": status,
        "data_directory_exists": data_exists,
        "processed_files": file_count,
        "events_count": events_count,
    })


@app.get("/api/live/status")
def live_status():
    status = monitor.status()
    status.update(vrp_cache.status())
    status["validation_data_note"] = (
        "Live event validation uses the shared VRP cache. "
        "The cache refreshes periodically from the RIPE Routinator export "
        "and retains the last-known-good snapshot if refresh fails."
    )
    return jsonify(status)


@app.get("/api/live/events")
def live_events():
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        return jsonify({"error": "Bad Request", "detail": "limit must be an integer", "status_code": 400}), 400
    if limit < 1 or limit > 1000:
        return jsonify({"error": "Bad Request", "detail": "limit must be between 1 and 1000", "status_code": 400}), 400
    return jsonify({"events": monitor.events(limit), "status": monitor.status()})


@app.post("/api/live/start")
def start_live_monitor():
    return jsonify({"status": monitor.start()}), 202


@app.post("/api/live/stop")
def stop_live_monitor():
    return jsonify({"status": monitor.stop()}), 200


@app.get("/api/events")
def get_events():
    try:
        data = load_dataset()
    except Exception:
        app.logger.exception("Failed to load study dataset for /api/events")
        return jsonify({"error": "Dataset Error", "detail": "Failed to load study dataset", "status_code": 500}), 500

    try:
        params = parse_event_filter_args(request.args)
    except ValueError as val_err:
        return jsonify({"error": "Bad Request", "detail": str(val_err), "status_code": 400}), 400

    try:
        filter_res = filter_events(
            events=data["events"],
            **params
        )
    except ValueError as val_err:
        return jsonify({"error": "Bad Request", "detail": str(val_err), "status_code": 400}), 400

    return jsonify({
        "events": filter_res["items"],
        "pagination": {
            "page": filter_res["page"],
            "page_size": filter_res["page_size"],
            "total_filtered": filter_res["total_filtered"],
            "total_unfiltered": filter_res["total_unfiltered"],
            "total_pages": filter_res["total_pages"],
            "has_next": filter_res["has_next"],
            "has_prev": filter_res["has_prev"],
        },
        "filters_applied": {
            "q": params["q"],
            "event_type": params["event_type"],
            "rpki_state": params["rpki_state"],
            "start": params["start"],
            "end": params["end"],
            "sort": params["sort"],
        },
    })


@app.get("/api/dashboard")
def dashboard_data():
    try:
        data = load_dataset()
    except Exception:
        app.logger.exception("Failed to load study dataset for /api/dashboard")
        return jsonify({"error": "Dataset Error", "detail": "Failed to load study dataset", "status_code": 500}), 500

    try:
        params = parse_event_filter_args(request.args)
    except ValueError as val_err:
        return jsonify({"error": "Bad Request", "detail": str(val_err), "status_code": 400}), 400

    try:
        filter_res = filter_events(
            events=data["events"],
            **params
        )
    except ValueError as val_err:
        return jsonify({"error": "Bad Request", "detail": str(val_err), "status_code": 400}), 400

    summary = data.get("summary", {})
    vrps = data.get("vrp_summary", [])
    events = data.get("events", [])

    unique_prefixes = summary.get("unique_prefixes")
    prefix = unique_prefixes[0] if (isinstance(unique_prefixes, list) and len(unique_prefixes) > 0) else None
    prefix_reason = None if prefix is not None else "No unique prefix found in summary"

    missing_evidence_count = sum(1 for e in events if e.get("origin_as") is None)

    rpki_state_counts = summary.get("rpki_state_counts")
    rpki_state_counts_reason = None if rpki_state_counts is not None else "No RPKI state counts in dataset summary"

    exact_prefix_authorized = None
    exact_prefix_authorized_reason = None
    if prefix and vrps:
        exact_prefix_authorized = any(v.get("prefix") == prefix for v in vrps if isinstance(v, dict))
    elif not vrps:
        exact_prefix_authorized_reason = "No covering ROA in dataset"
    else:
        exact_prefix_authorized_reason = "Prefix is missing"

    first_vrp = vrps[0] if (vrps and isinstance(vrps[0], dict)) else None
    max_length = first_vrp.get("max_length") if first_vrp else None
    max_length_reason = None if max_length is not None else "No covering ROA in dataset"

    origin_asn = first_vrp.get("origin_asn") if first_vrp else None
    origin_asn_reason = None if origin_asn is not None else "No covering ROA in dataset"

    synthetic_data_used = any(bool(e.get("synthetic", False)) for e in events)

    # Provide timeline points derived directly from real events (timestamp + type)
    timeline_events = [
        {
            "t": e.get("timestamp"),
            "type": e.get("event_type"),
            "prefix": e.get("prefix"),
            "source": e.get("source_id"),
            "path": e.get("as_path"),
            "rpki": e.get("rpki_state"),
        }
        for e in events
    ]

    return jsonify({
        "summary": {
            "prefix": prefix,
            "prefix_reason": prefix_reason,
            "events": int(summary.get("events_parsed", len(events))),
            "announcements": int((summary.get("event_type_counts") or {}).get("A", 0)),
            "withdrawals": int((summary.get("event_type_counts") or {}).get("W", 0)),
            "path_changes": int(data.get("observed_path_change_count", 0)),
            "announcements_after_withdrawals": int(data.get("announcement_after_withdrawal_count", 0)),
            "events_with_path": int(summary.get("events_with_path", 0)),
            "unique_source_ids": int(summary.get("unique_source_ids", 0)),
            "rpki_state_counts": rpki_state_counts,
            "rpki_state_counts_reason": rpki_state_counts_reason,
            "missing_evidence_count": missing_evidence_count,
        },
        "study_window": data["study_window"],
        "rpki_status": {
            "covering_roas": vrps,
            "exact_prefix_authorized": exact_prefix_authorized,
            "exact_prefix_authorized_reason": exact_prefix_authorized_reason,
            "max_length": max_length,
            "max_length_reason": max_length_reason,
            "origin_asn": origin_asn,
            "origin_asn_reason": origin_asn_reason,
            "stability_statement": (
                "No exact-prefix ROA change observed across snapshots; "
                "this does not prove continuous stability or reachability."
            ),
        },
        "events": filter_res["items"],
        "pagination": {
            "page": filter_res["page"],
            "page_size": filter_res["page_size"],
            "total_filtered": filter_res["total_filtered"],
            "total_unfiltered": filter_res["total_unfiltered"],
            "total_pages": filter_res["total_pages"],
            "has_next": filter_res["has_next"],
            "has_prev": filter_res["has_prev"],
        },
        "timeline_events": timeline_events,
        "path_length_distribution": data["path_length_distribution"],
        "path_stats": data["path_stats"],
        "snapshots": data["snapshots"],
        "sequences": data["sequences"],
        "sensitivity_analysis": data["sensitivity_analysis"],
        "limitations": data["limitations"],
        "synthetic_data_used": synthetic_data_used,
    })


@app.get("/api/events.csv")
def export_events():
    try:
        data = load_dataset()
    except Exception:
        app.logger.exception("Failed to load study dataset for CSV export")
        return jsonify({"error": "Dataset Error", "detail": "Failed to load study dataset", "status_code": 500}), 500

    try:
        params = parse_event_filter_args(request.args)
    except ValueError as val_err:
        return jsonify({"error": "Bad Request", "detail": str(val_err), "status_code": 400}), 400

    try:
        filter_res = filter_events(
            events=data["events"],
            q=params["q"],
            event_type=params["event_type"],
            rpki_state=params["rpki_state"],
            start=params["start"],
            end=params["end"],
            sort=params["sort"],
            page=1,
            page_size=1000,
        )
    except ValueError as val_err:
        return jsonify({"error": "Bad Request", "detail": str(val_err), "status_code": 400}), 400

    csv_data = export_events_csv(filter_res["all_filtered"])

    return Response(
        csv_data,
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=pathwatch_bgp_rpki_events.csv",
            "Content-Type": "text/csv; charset=utf-8",
        },
    )


if __name__ == "__main__":
    vrp_cache.start(refresh_immediately=True)
    app.run(host="127.0.0.1", port=8501, debug=False)
