"""
SOC Incident Ticketing Web App (Streamlit)
-----------------------------------------
A single-file Streamlit application for Security Operations Center (SOC) 
incident/ticket management.

Features
- Create incidents with SOC-specific fields (severity/priority, category, IOCs, asset, tags)
- File evidence upload (stores to ./uploads and path in DB)
- Queue view with powerful filters (status, severity, assignee, text search, date range)
- Ticket detail page with updates (status, assignee, severity), comments/timeline, evidence add
- SLA due time auto-calculation by severity (customizable)
- CSV export of current filtered queue
- Simple role hint (Analyst/Lead/Manager) to tailor available actions (not strict auth)
- Lightweight persistence with SQLite (soc_tickets.db)

How to run
1) Install deps:  
   pip install streamlit pandas python-dateutil
2) Start app:  
   streamlit run soc_ticketing.py

Notes
- This is a basic starter you can adapt. For real production, add SSO, RBAC, audit logging, and backups.
- Evidence is saved under ./uploads/<ticket_id>/ .
- Timezone uses system time.
"""

import os
import re
import io
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from dateutil import tz
from typing import Optional, Dict, Any, List

import pandas as pd
import streamlit as st

DB_PATH = "soc_tickets.db"
UPLOAD_ROOT = "uploads"

# ----------------------------- Utilities -----------------------------

def now_utc_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

@contextmanager
def get_conn(path: str = DB_PATH):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.commit()
        conn.close()

# ----------------------------- DB Init -------------------------------

SCHEMA_SQL = r"""
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'Medium', -- Critical, High, Medium, Low
    status TEXT NOT NULL DEFAULT 'New',      -- New, In Progress, Contained, Resolved, Closed
    category TEXT,                           -- Malware, Phishing, IDS Alert, DLP, Insider, Vuln, Other
    reporter TEXT,
    assignee TEXT,
    asset TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    tags TEXT,
    due_at TEXT,                             -- ISO UTC
    created_at TEXT NOT NULL,                -- ISO UTC
    updated_at TEXT NOT NULL                 -- ISO UTC
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    author TEXT,
    comment TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    uploaded_by TEXT,
    uploaded_at TEXT NOT NULL,
    FOREIGN KEY(ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
);
"""

DEFAULT_SLA_HOURS = {
    "Critical": 4,
    "High": 8,
    "Medium": 24,
    "Low": 72,
}

@st.cache_resource(show_spinner=False)
def init_db():
    os.makedirs(UPLOAD_ROOT, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA_SQL)
    return True

init_db()

# --------------------------- Helper Logic ----------------------------

def calc_due_at(severity: str, created_at_iso: Optional[str] = None) -> str:
    created = datetime.utcnow() if created_at_iso is None else datetime.fromisoformat(created_at_iso.replace("Z", ""))
    hours = DEFAULT_SLA_HOURS.get(severity, 24)
    return (created + timedelta(hours=hours)).replace(microsecond=0).isoformat() + "Z"

def insert_ticket(data: Dict[str, Any]) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO tickets(title, description, severity, status, category, reporter, assignee, asset, src_ip, dst_ip, tags, due_at, created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                data.get("title"), data.get("description"), data.get("severity"), data.get("status"),
                data.get("category"), data.get("reporter"), data.get("assignee"), data.get("asset"),
                data.get("src_ip"), data.get("dst_ip"), data.get("tags"), data.get("due_at"),
                data.get("created_at"), data.get("updated_at"),
            ),
        )
        return cur.lastrowid

def update_ticket(ticket_id: int, fields: Dict[str, Any]):
    if not fields:
        return
    keys = ", ".join([f"{k} = ?" for k in fields.keys()])
    values = list(fields.values()) + [ticket_id]
    with get_conn() as conn:
        conn.execute(f"UPDATE tickets SET {keys} WHERE id = ?", values)

def add_comment(ticket_id: int, author: str, comment: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO comments(ticket_id, author, comment, created_at) VALUES(?,?,?,?)",
            (ticket_id, author, comment, now_utc_iso()),
        )

def add_evidence(ticket_id: int, file_name: str, file_path: str, uploaded_by: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO evidence(ticket_id, file_name, file_path, uploaded_by, uploaded_at) VALUES(?,?,?,?,?)",
            (ticket_id, file_name, file_path, uploaded_by, now_utc_iso()),
        )

@st.cache_data(ttl=5)
def get_ticket_df():
    with get_conn() as conn:
        df = pd.read_sql_query("SELECT * FROM tickets ORDER BY id DESC", conn)
    return df

def get_ticket(ticket_id: int) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        cur = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,))
        row = cur.fetchone()
    return row

def get_comments(ticket_id: int) -> pd.DataFrame:
    with get_conn() as conn:
        df = pd.read_sql_query(
            "SELECT author, comment, created_at FROM comments WHERE ticket_id = ? ORDER BY id DESC",
            conn,
            params=(ticket_id,),
        )
    return df

def get_evidence(ticket_id: int) -> pd.DataFrame:
    with get_conn() as conn:
        df = pd.read_sql_query(
            "SELECT file_name, file_path, uploaded_by, uploaded_at FROM evidence WHERE ticket_id = ? ORDER BY id DESC",
            conn,
            params=(ticket_id,),
        )
    return df

# ------------------------------ UI ----------------------------------

st.set_page_config(page_title="SOC Incident Ticketing", page_icon="🛡️", layout="wide")

if "role" not in st.session_state:
    st.session_state.role = "Analyst"
if "user" not in st.session_state:
    st.session_state.user = "analyst@local"

st.title("🛡️ SOC Incident Ticketing")
with st.sidebar:
    st.header("User & View")
    st.session_state.user = st.text_input("Your name/email", st.session_state.user)
    st.session_state.role = st.selectbox("Role (hint)", ["Analyst", "Lead", "Manager"], index=["Analyst","Lead","Manager"].index(st.session_state.role))

    st.markdown("---")
    page = st.radio("Navigate", ["Create Ticket", "Ticket Queue", "Ticket Detail", "Reports & SLA", "Settings"], index=1)

# --------------------------- Create Ticket ---------------------------

if page == "Create Ticket":
    st.subheader("Create New Incident")
    with st.form("create_ticket_form", clear_on_submit=True):
        c1, c2 = st.columns(2)
        with c1:
            title = st.text_input("Title*", placeholder="Phishing email reported by CEO")
            severity = st.selectbox("Severity*", ["Critical", "High", "Medium", "Low"], index=2)
            category = st.selectbox("Category", ["Malware", "Phishing", "IDS Alert", "DLP", "Insider", "Vuln", "Other"], index=2)
            asset = st.text_input("Asset (hostname / IP)")
            tags = st.text_input("Tags (comma-separated)")
        with c2:
            reporter = st.text_input("Reporter", value=st.session_state.user)
            assignee = st.text_input("Assignee", placeholder="on-call@sec")
            src_ip = st.text_input("Source IP")
            dst_ip = st.text_input("Destination IP")
        description = st.text_area("Description", height=150, placeholder="Summary, observed alerts, initial triage notes...")
        submitted = st.form_submit_button("Create Ticket", type="primary")

    if submitted:
        if not title.strip():
            st.error("Title is required")
        else:
            created_at = now_utc_iso()
            due_at = calc_due_at(severity, created_at)
            tid = insert_ticket({
                "title": title.strip(),
                "description": description.strip(),
                "severity": severity,
                "status": "New",
                "category": category,
                "reporter": reporter.strip(),
                "assignee": assignee.strip(),
                "asset": asset.strip(),
                "src_ip": src_ip.strip(),
                "dst_ip": dst_ip.strip(),
                "tags": tags.strip(),
                "due_at": due_at,
                "created_at": created_at,
                "updated_at": created_at,
            })
            st.success(f"Ticket #{tid} created")
            st.cache_data.clear()

# --------------------------- Ticket Queue ----------------------------

elif page == "Ticket Queue":
    st.subheader("Queue & Filters")

    df = get_ticket_df()

    with st.expander("Filters", expanded=True):
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            f_status = st.multiselect("Status", sorted(df["status"].unique().tolist() if not df.empty else []), default=[])
        with c2:
            f_sev = st.multiselect("Severity", ["Critical","High","Medium","Low"], default=[])
        with c3:
            f_assignee = st.text_input("Assignee contains")
        with c4:
            f_text = st.text_input("Search text (title/desc/tags/IP)")
        d1, d2, d3 = st.columns([1,1,2])
        with d1:
            start = st.date_input("From date", value=None)
        with d2:
            end = st.date_input("To date", value=None)
        with d3:
            pass

    if not df.empty:
        m = pd.Series([True]*len(df))
        if f_status:
            m &= df['status'].isin(f_status)
        if f_sev:
            m &= df['severity'].isin(f_sev)
        if f_assignee:
            m &= df['assignee'].fillna("").str.contains(f_assignee, case=False, na=False)
        if f_text:
            hay = df[['title','description','tags','src_ip','dst_ip','asset']].astype(str).agg(' '.join, axis=1)
            m &= hay.str.contains(re.escape(f_text), case=False, na=False)
        if start:
            m &= pd.to_datetime(df['created_at'].str.replace('Z','')) >= pd.to_datetime(start)
        if end:
            m &= pd.to_datetime(df['created_at'].str.replace('Z','')) <= pd.to_datetime(end) + pd.Timedelta(days=1)
        fdf = df[m].copy()

        # Color helper for SLA
        def sla_state(row):
            due = pd.to_datetime(row['due_at'].replace('Z','')) if pd.notna(row['due_at']) else None
            if due is None:
                return "Unknown"
            delta = due - datetime.utcnow()
            if delta.total_seconds() < 0:
                return "Overdue"
            elif delta <= timedelta(hours=2):
                return "Due Soon"
            return "OK"

        if not fdf.empty:
            fdf['SLA'] = fdf.apply(sla_state, axis=1)
            view = fdf[['id','title','severity','status','assignee','category','asset','created_at','due_at','SLA']]
            st.dataframe(view, use_container_width=True, hide_index=True)

            st.download_button(
                label="Export CSV (filtered)",
                data=view.to_csv(index=False).encode('utf-8'),
                file_name="soc_ticket_queue.csv",
                mime="text/csv",
            )

            st.markdown("### Open a ticket")
            tid = st.number_input("Ticket ID", min_value=1, step=1)
            if st.button("Open Ticket #", type="primary"):
                st.session_state.selected_ticket_id = int(tid)
                st.switch_page("/Ticket_Detail") if hasattr(st, 'switch_page') else None
        else:
            st.info("No tickets match the filters.")
    else:
        st.info("No tickets in database yet. Create the first one.")

# --------------------------- Ticket Detail ---------------------------

elif page == "Ticket Detail":
    st.subheader("Ticket Detail & Updates")

    # Provide a way to select a ticket
    df = get_ticket_df()
    ids = df['id'].tolist() if not df.empty else []
    if not ids:
        st.info("No tickets found. Create one first.")
    else:
        default_idx = 0
        if 'selected_ticket_id' in st.session_state and st.session_state.selected_ticket_id in ids:
            default_idx = ids.index(st.session_state.selected_ticket_id)
        sel_id = st.selectbox("Select Ticket ID", ids, index=default_idx)
        rec = get_ticket(int(sel_id))
        if not rec:
            st.error("Ticket not found.")
        else:
            rec = dict(rec)
            c1, c2, c3 = st.columns([2,1,1])
            with c1:
                st.markdown(f"### #{rec['id']} — {rec['title']}")
                st.write(rec['description'])
            with c2:
                st.metric("Severity", rec['severity'])
                st.metric("Status", rec['status'])
            with c3:
                st.metric("Assignee", rec['assignee'] or "-")
                st.metric("SLA Due", rec['due_at'] or "-")

            st.markdown("---")
            st.markdown("#### SOC Fields")
            c4, c5, c6 = st.columns(3)
            with c4:
                st.write(f"**Category:** {rec['category'] or '-'}")
                st.write(f"**Asset:** {rec['asset'] or '-'}")
            with c5:
                st.write(f"**Src IP:** {rec['src_ip'] or '-'}")
                st.write(f"**Dst IP:** {rec['dst_ip'] or '-'}")
            with c6:
                st.write(f"**Tags:** {rec['tags'] or '-'}")

            st.markdown("---")
            st.markdown("#### Update Ticket")
            up1, up2, up3, up4 = st.columns(4)
            with up1:
                new_status = st.selectbox("Status", ["New","In Progress","Contained","Resolved","Closed"], index=["New","In Progress","Contained","Resolved","Closed"].index(rec['status']))
            with up2:
                new_sev = st.selectbox("Severity", ["Critical","High","Medium","Low"], index=["Critical","High","Medium","Low"].index(rec['severity']))
            with up3:
                new_assignee = st.text_input("Assignee", value=rec['assignee'] or "")
            with up4:
                recalc_sla = st.checkbox("Recalculate SLA on severity change", value=True)

            if st.button("Save Changes", type="primary"):
                updates = {}
                if new_status != rec['status']:
                    updates['status'] = new_status
                if new_sev != rec['severity']:
                    updates['severity'] = new_sev
                    if recalc_sla:
                        updates['due_at'] = calc_due_at(new_sev, rec['created_at'])
                if new_assignee != (rec['assignee'] or ""):
                    updates['assignee'] = new_assignee
                if updates:
                    updates['updated_at'] = now_utc_iso()
                    update_ticket(rec['id'], updates)
                    add_comment(rec['id'], st.session_state.user, f"Updated fields: {', '.join(updates.keys())}")
                    st.success("Ticket updated.")
                    st.cache_data.clear()
                else:
                    st.info("No changes to save.")

            st.markdown("---")
            st.markdown("#### Add Comment")
            comment = st.text_area("Comment", placeholder="Investigation steps, commands, containment actions...")
            if st.button("Add Comment"):
                if comment.strip():
                    add_comment(rec['id'], st.session_state.user, comment.strip())
                    st.success("Comment added.")
                else:
                    st.error("Comment cannot be empty.")

            st.markdown("#### Upload Evidence")
            up_ev_col1, up_ev_col2 = st.columns([2,1])
            with up_ev_col1:
                f = st.file_uploader("Upload file (pcap, txt, screenshot, etc.)", accept_multiple_files=False)
            with up_ev_col2:
                if f and st.button("Attach Evidence"):
                    ticket_dir = os.path.join(UPLOAD_ROOT, str(rec['id']))
                    os.makedirs(ticket_dir, exist_ok=True)
                    save_path = os.path.join(ticket_dir, f.name)
                    with open(save_path, 'wb') as out:
                        out.write(f.getbuffer())
                    add_evidence(rec['id'], f.name, save_path, st.session_state.user)
                    st.success(f"Saved to {save_path}")

            st.markdown("---")
            st.markdown("#### Timeline & Evidence")
            cmt_df = get_comments(rec['id'])
            if not cmt_df.empty:
                st.write("**Comments**")
                st.dataframe(cmt_df, use_container_width=True, hide_index=True)
            else:
                st.info("No comments yet.")

            ev_df = get_evidence(rec['id'])
            if not ev_df.empty:
                st.write("**Evidence**")
                for _, r in ev_df.iterrows():
                    st.write(f"📎 {r['file_name']} — uploaded by {r['uploaded_by']} @ {r['uploaded_at']}")
                    try:
                        with open(r['file_path'], 'rb') as fh:
                            st.download_button(
                                label=f"Download {r['file_name']}",
                                data=fh.read(),
                                file_name=r['file_name']
                            )
                    except Exception:
                        st.warning(f"File missing: {r['file_path']}")
            else:
                st.info("No evidence uploaded.")

# --------------------------- Reports & SLA ---------------------------

elif page == "Reports & SLA":
    st.subheader("Operational Overview")
    df = get_ticket_df()
    if df.empty:
        st.info("No data to report yet.")
    else:
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Tickets", len(df))
        c2.metric("Open (non-Closed)", int((df['status'] != 'Closed').sum()))
        overdue = 0
        now = datetime.utcnow()
        for _, r in df.iterrows():
            if pd.notna(r['due_at']):
                due = datetime.fromisoformat(str(r['due_at']).replace('Z',''))
                if due < now and r['status'] != 'Closed':
                    overdue += 1
        c3.metric("Overdue", overdue)

        st.markdown("### Breakdown")
        colA, colB = st.columns(2)
        with colA:
            st.write("By Severity")
            st.bar_chart(df['severity'].value_counts())
        with colB:
            st.write("By Status")
            st.bar_chart(df['status'].value_counts())

        st.markdown("### SLA By Severity (Hours)")
        sla_df = pd.DataFrame({
            'Severity': list(DEFAULT_SLA_HOURS.keys()),
            'SLA Hours': list(DEFAULT_SLA_HOURS.values())
        })
        st.dataframe(sla_df, hide_index=True, use_container_width=True)

# ------------------------------ Settings ----------------------------

elif page == "Settings":
    st.subheader("Settings")
    st.write("Adjust SLA hours (affects new due times)")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        DEFAULT_SLA_HOURS['Critical'] = st.number_input("Critical (h)", min_value=1, max_value=168, value=DEFAULT_SLA_HOURS['Critical'])
    with c2:
        DEFAULT_SLA_HOURS['High'] = st.number_input("High (h)", min_value=1, max_value=168, value=DEFAULT_SLA_HOURS['High'])
    with c3:
        DEFAULT_SLA_HOURS['Medium'] = st.number_input("Medium (h)", min_value=1, max_value=168, value=DEFAULT_SLA_HOURS['Medium'])
    with c4:
        DEFAULT_SLA_HOURS['Low'] = st.number_input("Low (h)", min_value=1, max_value=168, value=DEFAULT_SLA_HOURS['Low'])

    st.info("SLA changes apply when creating tickets or when you choose to recalculate on severity change.")

    st.markdown("---")
    st.write("Maintenance")
    if st.button("Rebuild DB (keeps data)"):
        init_db()
        st.success("Schema ensured.")

    if st.button("Wipe ALL Data ⚠️"):
        with get_conn() as conn:
            conn.execute("DELETE FROM evidence")
            conn.execute("DELETE FROM comments")
            conn.execute("DELETE FROM tickets")
        # also clear uploads
        try:
            import shutil
            if os.path.isdir(UPLOAD_ROOT):
                shutil.rmtree(UPLOAD_ROOT)
            os.makedirs(UPLOAD_ROOT, exist_ok=True)
        except Exception:
            pass
        st.cache_data.clear()
        st.success("All data wiped.")

st.caption("© 2025 SOC Ticketing Starter · Streamlit")
