# gui.py
"""
Streamlit GUI for Mini Port & Service Scanner
Place this file in the project root (next to the port_scanner package).
Run with:
    streamlit run gui.py
"""

import io
import json
import pandas as pd
import streamlit as st
from datetime import datetime, timezone
from typing import List, Dict, Any

# Import the package helper that provides a synchronous wrapper
import port_scanner

st.set_page_config(page_title="Mini Port & Service Scanner", layout="wide")

APP_TITLE = "🔐 Mini Port & Service Scanner (Mini-Nmap Clone)"
st.title(APP_TITLE)

with st.expander("Legal & Ethical Notice (click to expand)", expanded=True):
    st.warning(
        """
        **Important:** Do NOT scan systems you do not own or have explicit authorization to test.
        Unauthorized scanning can be illegal. Use this tool only on your own assets, lab networks,
        or targets for which you have written permission (bug bounty targets, authorized pentests).
        """
    )

# Sidebar inputs
st.sidebar.header("Scan settings")

default_target = "127.0.0.1"
target = st.sidebar.text_input("Target (IP or domain)", value=default_target)

ports_input = st.sidebar.text_input(
    "Ports (CSV / ranges). Examples: 22,80,443  or  1-1024  or leave blank for top ports",
    value=",".join(map(str, port_scanner.TOP_TCP_PORTS)),
)

timeout = st.sidebar.number_input("TCP connect timeout (seconds)", min_value=0.1, value=3.0, step=0.1)
concurrency = st.sidebar.number_input("Max concurrency", min_value=1, value=200, step=1)
only_open = st.sidebar.checkbox("Show only open ports in table", value=True)
output_prefix = st.sidebar.text_input("Output filename prefix (optional)", value="scan")

# Helper: parse ports input (same logic as scanner.parse_ports)
def parse_ports_input(s: str) -> List[int]:
    if not s or s.strip() == "":
        return list(port_scanner.TOP_TCP_PORTS)
    parts = [p.strip() for p in s.split(",") if p.strip()]
    ports = set()
    for part in parts:
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start_i = int(start)
                end_i = int(end)
                ports.update(range(start_i, end_i + 1))
            except Exception:
                continue
        else:
            try:
                ports.add(int(part))
            except Exception:
                continue
    return sorted([p for p in ports if 1 <= p <= 65535])

# Action
col1, col2 = st.columns([3, 1])
with col1:
    if st.button("Start scan", key="start"):
        # Parse ports
        ports = parse_ports_input(ports_input)
        st.info(f"Starting scan of **{target}** — {len(ports)} ports. Timeout={timeout}s, concurrency={concurrency}")
        # Run the scan inside a spinner
        with st.spinner("Scanning (this may take a few seconds)..."):
            try:
                results: List[Dict[str, Any]] = port_scanner.run_scan_sync(
                    target=target, ports=ports, timeout=timeout, concurrency=concurrency
                )
            except Exception as exc:
                st.error(f"Scan failed: {exc}")
                results = []

        # Post-process results into DataFrame
        if not results:
            st.warning("No results returned. Check target/permissions and try again.")
        else:
            # attach metadata
            scanned_at = datetime.now(timezone.utc).isoformat()
            meta = {"target": target, "scanned_at": scanned_at, "ports_scanned": len(ports)}
            st.success(f"Scan finished — {len([r for r in results if r['status']=='open'])} open ports found")

            df = pd.DataFrame(results)
            # Normalize banner -> safe string
            df["banner"] = df["banner"].fillna("").astype(str).str.replace("\r", " ", regex=False).str.replace("\n", " ", regex=False)
            df["service"] = df["service"].fillna("")

            # Optionally filter to only open ports
            display_df = df[df["status"] == "open"] if only_open else df

            st.subheader("Scan results")
            st.dataframe(display_df.reset_index(drop=True), use_container_width=True)

            # Provide downloads (CSV & JSON)
            csv_buffer = io.StringIO()
            display_df.to_csv(csv_buffer, index=False)
            csv_bytes = csv_buffer.getvalue().encode("utf-8")

            json_payload = {
                "meta": meta,
                "results": results
            }
            json_bytes = json.dumps(json_payload, indent=2, ensure_ascii=False).encode("utf-8")

            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            json_name = f"{output_prefix}_{timestamp}.json"
            csv_name = f"{output_prefix}_{timestamp}.csv"

            col_dl1, col_dl2 = st.columns(2)
            with col_dl1:
                st.download_button("Download CSV", data=csv_bytes, file_name=csv_name, mime="text/csv")
            with col_dl2:
                st.download_button("Download JSON", data=json_bytes, file_name=json_name, mime="application/json")

            # Quick visuals: small bar of open vs closed
            counts = df["status"].value_counts().to_dict()
            open_count = int(counts.get("open", 0))
            closed_count = int(counts.get("closed", 0))
            st.markdown("**Summary**")
            st.metric("Open ports", open_count)
            st.metric("Closed ports", closed_count)

# Footer tips
st.markdown("---")
st.markdown(
    """
**Tips**
- If you see no open ports but expect some, confirm the target is reachable and not blocking scans.
- Keep `concurrency` moderate on external targets to avoid accidental DoS.
- For production pentests use authorized tooling and follow rules of engagement.
"""
)
