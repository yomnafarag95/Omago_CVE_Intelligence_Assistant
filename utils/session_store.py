"""
utils/session_store.py
───────────────────────
Saves and loads chat sessions to/from a local JSON file.
Each session stores: id, title, timestamp, messages list.

File location: data/chat_sessions.json
"""

import json
import os
import uuid
from datetime import datetime
from typing import List, Dict, Optional

SESSIONS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "chat_sessions.json")


def _ensure_file():
    """Create the sessions file and data dir if they don't exist."""
    os.makedirs(os.path.dirname(SESSIONS_FILE), exist_ok=True)
    if not os.path.exists(SESSIONS_FILE):
        with open(SESSIONS_FILE, "w") as f:
            json.dump([], f)


def load_all_sessions() -> List[Dict]:
    """Return all saved chat sessions, newest first."""
    _ensure_file()
    try:
        with open(SESSIONS_FILE, "r") as f:
            sessions = json.load(f)
        return sorted(sessions, key=lambda s: s.get("timestamp", ""), reverse=True)
    except Exception:
        return []


def save_session(session: Dict):
    """
    Upsert a session by its id.
    If a session with the same id exists, it is replaced.
    """
    _ensure_file()
    sessions = load_all_sessions()
    sessions = [s for s in sessions if s.get("id") != session.get("id")]
    sessions.insert(0, session)
    # Keep only the 50 most recent sessions
    sessions = sessions[:50]
    with open(SESSIONS_FILE, "w") as f:
        json.dump(sessions, f, indent=2)


def new_session(first_message: str = "") -> Dict:
    """Create a new session dict."""
    now = datetime.now()
    title = first_message[:40].strip() if first_message else f"Session {now.strftime('%b %d %H:%M')}"
    return {
        "id": str(uuid.uuid4()),
        "title": title,
        "timestamp": now.isoformat(),
        "messages": [],
    }


def delete_session(session_id: str):
    """Remove a session by ID."""
    _ensure_file()
    sessions = load_all_sessions()
    sessions = [s for s in sessions if s.get("id") != session_id]
    with open(SESSIONS_FILE, "w") as f:
        json.dump(sessions, f, indent=2)


def get_session(session_id: str) -> Optional[Dict]:
    """Fetch a single session by ID."""
    for s in load_all_sessions():
        if s.get("id") == session_id:
            return s
    return None


def append_message(session_id: str, role: str, content: str):
    """Add a message to an existing session and persist."""
    session = get_session(session_id)
    if not session:
        return
    session["messages"].append({"role": role, "content": content})
    # Update title from first user message if still generic
    user_msgs = [m for m in session["messages"] if m["role"] == "user"]
    if len(user_msgs) == 1:
        session["title"] = user_msgs[0]["content"][:45].strip()
    save_session(session)
