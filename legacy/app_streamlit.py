
import json
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).parent
PROCESSED = ROOT / "data" / "processed"

st.set_page_config(
    page_title="RPKI-PathWatch",
    page_icon="🌐",
    layout="wide",
)

st.title("🌐 RPKI-PathWatch")
st.subheader("BGP Path and Route Visibility Analysis")
st.caption("Internet Measurements | PS-032 | Team A3-PS032-TC538")

st.info(
    "Historical RPKI snapshot correlation is now implemented. "
    "Validation states are inferred from daily snapshots, not continuous observations."
)


def load_json(filename):
    path = PROCESSED / filename
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return None


updates = load_json("bgp_updates_summary.json")
analysis = load_json("route_event_analysis.json")
snapshots = load_json("snapshot_comparison.json")
if snapshots is None:
    snapshots = load_json("comparison_summary.json")

rpki_history = load_json("rpki_history_summary.json")
correlation = load_json("rpki_bgp_correlation.json")

# RPKI snapshot history and BGP correlation
st.header("Historical RPKI Validation")

if rpki_history:
    scope = rpki_history.get("scope", {})
    history_rows = rpki_history.get("snapshots", [])

    col1, col2, col3 = st.columns(3)
    col1.metric("Study prefix", scope.get("prefix", "N/A"))
    col2.metric("Observed origin AS", f"AS{scope['origin_as']}" if scope.get("origin_as") is not None else "N/A")
    col3.metric("Daily snapshots", len(history_rows))

    if history_rows:
        history_df = pd.DataFrame(history_rows)
        display_columns = [
            "snapshot_time",
            "snapshot_file",
            "target_prefix",
            "observed_origin_as",
            "validation_state",
            "usable_vrp_count",
        ]
        available_columns = [
            column for column in display_columns
            if column in history_df.columns
        ]
        st.dataframe(
            history_df[available_columns],
            use_container_width=True,
            hide_index=True,
        )

        if "validation_state" in history_df.columns:
            st.subheader("Validation state by snapshot")
            st.bar_chart(
                history_df["validation_state"].value_counts()
            )
else:
    st.warning(
        "RPKI history summary not found. "
        "Expected data/processed/rpki_history_summary.json."
    )

st.header("BGP–RPKI Event Correlation")

if correlation:
    event_counts = correlation.get("event_type_counts", {})
    state_counts = correlation.get("rpki_state_counts", {})
    events = correlation.get("events", [])

    col1, col2, col3 = st.columns(3)
    col1.metric("Correlated BGP events", correlation.get("event_count", len(events)))
    col2.metric("Announcements", event_counts.get("A", 0))
    col3.metric("Withdrawals", event_counts.get("W", 0))

    st.subheader("Inferred RPKI state counts")
    state_df = pd.DataFrame(
        [{"Validation state": state, "Events": count}
         for state, count in state_counts.items()]
    )
    if not state_df.empty:
        st.dataframe(state_df, use_container_width=True, hide_index=True)

    if events:
        event_df = pd.DataFrame(events)

        # Interactive filters apply to the actual event records.
        if "prefix" in event_df.columns:
            prefixes = sorted(
                event_df["prefix"].dropna().unique().tolist()
            )
            selected_prefixes = st.multiselect(
                "Filter prefixes",
                options=prefixes,
                default=prefixes,
            )
            event_df = event_df[event_df["prefix"].isin(selected_prefixes)]

        if "event_type" in event_df.columns:
            event_types = sorted(
                event_df["event_type"].dropna().unique().tolist()
            )
            selected_types = st.multiselect(
                "Filter event types",
                options=event_types,
                default=event_types,
            )
            event_df = event_df[event_df["event_type"].isin(selected_types)]

        if "rpki_state" in event_df.columns:
            states = sorted(
                event_df["rpki_state"].fillna("Unassigned").unique().tolist()
            )
            selected_states = st.multiselect(
                "Filter inferred RPKI states",
                options=states,
                default=states,
            )
            normalized_states = event_df["rpki_state"].fillna("Unassigned")
            event_df = event_df[normalized_states.isin(selected_states)]

        st.caption(f"Showing {len(event_df)} matching events.")
        preferred_columns = [
            "timestamp",
            "event_type",
            "prefix",
            "source_id",
            "origin_as",
            "rpki_state",
            "rpki_snapshot",
            "rpki_time_gap_seconds",
            "status_note",
        ]
        visible_columns = [
            column for column in preferred_columns
            if column in event_df.columns
        ]
        st.dataframe(
            event_df[visible_columns],
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download filtered correlation as CSV",
            data=event_df.to_csv(index=False).encode("utf-8"),
            file_name="rpki_bgp_correlation_filtered.csv",
            mime="text/csv",
        )

    with st.expander("Correlation method and limitations"):
        st.write(correlation.get("correlation_method", "Method not specified."))
        for limitation in correlation.get("limitations", []):
            st.warning(limitation)

    for limitation in rpki_history.get("limitations", []):
        st.caption(f"Snapshot limitation: {limitation}")
else:
    st.warning(
        "Correlation data not found. "
        "Run python -m src.correlate_rpki_bgp first."
    )

st.header("BGP Update Analysis")

if updates:
    st.json(updates, expanded=True)
else:
    st.warning("Update summary not found. Run src/analyze_updates.py.")

st.header("Route Event Reconstruction")

if analysis:
    event_counts = analysis.get("event_counts", {})
    if not isinstance(event_counts, dict):
        event_counts = {}

    col1, col2, col3 = st.columns(3)
    col1.metric("Input BGP events", analysis.get("input_events", 266))
    col2.metric("Observed path changes", analysis.get("path_changes", 112))
    col3.metric(
        "Announcements after withdrawals",
        analysis.get("announcements_after_withdrawals", 3),
    )

    if event_counts:
        st.write("Event counts")
        st.bar_chart(pd.Series(event_counts, name="Events"))

    sequences = analysis.get("sequences", [])
    if isinstance(sequences, list) and sequences:
        st.subheader("Reconstructed event sequences")
        st.dataframe(pd.DataFrame(sequences), use_container_width=True)

    st.subheader("Analysis output")
    st.json(analysis, expanded=False)
else:
    st.warning(
        "Route analysis not found. Run src/reconstruct_routes.py first."
    )

st.header("Snapshot Comparison")

if snapshots:
    st.json(snapshots, expanded=True)
else:
    st.caption(
        "Snapshot comparison summary was not found under the expected "
        "filenames. The comparison output remains available in "
        "data/processed."
    )

st.header("Data and Methodology")
st.markdown("""
- **BGP source:** RIPE Stat historical BGP state and update data.
- **RPKI source:** RIPE NCC daily RPKI archive snapshots.
- **Study prefix:** `193.0.0.0/21`.
- **Collected BGP update window:** 20–23 December 2024, based on the configured query interval.
- **Validation method:** validate the last AS in each announcement's AS path against the latest available snapshot dated at or before that event.
- **Interpretation:** snapshot-based temporal correlation does not establish continuous RPKI state, global reachability, or causation.
""")

st.caption("RPKI-PathWatch | Research prototype")
