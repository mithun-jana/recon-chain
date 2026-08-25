"""
Wordlist storage for directory fuzzing.
"""
from __future__ import annotations

import os
import uuid

from sqlmodel import Session

from app.models import Wordlist

WORDLISTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists")
UPLOADS_DIR = os.path.join(WORDLISTS_DIR, "uploads")
DEFAULT_WORDLIST_PATH = os.path.join(WORDLISTS_DIR, "default.txt")

os.makedirs(UPLOADS_DIR, exist_ok=True)


def save_uploaded_wordlist(session: Session, filename: str, content: bytes) -> Wordlist:
    text = content.decode("utf-8", errors="ignore")
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]

    wordlist_id = uuid.uuid4().hex
    path = os.path.join(UPLOADS_DIR, f"{wordlist_id}.txt")
    with open(path, "w") as f:
        f.write("\n".join(lines))

    record = Wordlist(
        wordlist_id=wordlist_id,
        original_filename=filename,
        line_count=len(lines),
    )
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


def get_wordlist_path(wordlist_id: str | None) -> str:

    if wordlist_id:
        path = os.path.join(UPLOADS_DIR, f"{wordlist_id}.txt")
        if os.path.isfile(path):
            return path
    return DEFAULT_WORDLIST_PATH


def load_wordlist_words(wordlist_id: str | None) -> list[str]:
    path = get_wordlist_path(wordlist_id)
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]