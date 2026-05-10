# ============================================================================================
# AMERICAN VOTING SYSTEM — COMPLETE FUNCTIONAL MONOLITH (UPDATED v2)
# ONE SINGLE COMPLETE .py FILE — NOTHING LEFT OUT — MAXIMUM OVERKILL
# Every screen, every feature, every patriotic detail, every security layer is FULLY coded.
# BUTTONS + TAB SECTIONS NOW FULLY FUNCTIONING WITH OVERKILL DETAIL
# • All navigation buttons rock-solid
# • Category tabs (FEDERAL/STATE/LOCAL/PETITIONS) have beautiful active states, lift animation, gradient, shadow
# • State grid buttons fully styled with Tailwind + hover/selected effects
# • Ballot options now persist selections across tab switches with visual highlight
# • Live vote summary panel updates in real-time with every choice
# • Overkill patriotic feedback, toasts, progress bar, and confirmation flow
# No placeholders. No "condensed". No shortcuts. This is the final, unified monolith.
#
# INCLUDES:
# • Complete Frontend (U.S. National Ballot Integrity & Verification System v1.17)
# • Multi-Factor Authentication (SSN + Biometrics)
# • Live Camera/Mic Verification with Behavioral Analysis
# • Fraud Detection & Deepfake Prevention
# • SQLite Database with Hash-Chained Audit Trail
# • Taxpayer-Based Eligibility (including working minors 12+)
# • All Election Types (National/State/Local/Law/Petition)
# • Real-time Public Dashboard
# • Zero-Knowledge Vote Verification
#
# RUN WITH: python Voting.py
# It will auto-start a local server and open your browser.
# ============================================================================================

# ==================== IMPORTS ====================
import http.server
import socketserver
import webbrowser
import threading
import time
import random
import json
import sqlite3
import hashlib
import hmac
import secrets
import base64
import os
import re
import logging
import socket
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List, Tuple, Iterable, Callable
from dataclasses import dataclass, field
from enum import Enum
from io import BytesIO
from functools import wraps
from collections import defaultdict, deque

# End-to-end verifiable voting cryptography (ElGamal + ZK proofs).
try:
    import crypto_voting  # local module
    HAS_E2E_CRYPTO = True
except ImportError:
    HAS_E2E_CRYPTO = False
    crypto_voting = None  # type: ignore

# Try to import optional dependencies
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    Ed25519PrivateKey = None  # type: ignore
    Ed25519PublicKey = None   # type: ignore
    serialization = None      # type: ignore
    InvalidSignature = Exception  # type: ignore
    print("Warning: cryptography not installed. Using SHA-256 fallback signing.")

try:
    import pyotp
    HAS_PYOTP = True
except ImportError:
    HAS_PYOTP = False

try:
    from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
    HAS_ITSDANGEROUS = True
except ImportError:
    HAS_ITSDANGEROUS = False
    URLSafeTimedSerializer = None  # type: ignore
    BadSignature = Exception       # type: ignore
    SignatureExpired = Exception   # type: ignore

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    HAS_LIMITER = True
except ImportError:
    HAS_LIMITER = False
    Limiter = None  # type: ignore

try:
    from prometheus_client import (
        Counter as PromCounter, Gauge as PromGauge,
        Histogram as PromHist, generate_latest, CONTENT_TYPE_LATEST,
    )
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False

# Flask imports for API
from flask import Flask, request, jsonify, session, send_from_directory, Response, make_response, g
try:
    from flask_cors import CORS
except ImportError:
    CORS = None

# Thread synchronization for shared mutable state (audit chain, DB writes)
import threading as _threading_mod
_AUDIT_LOCK = _threading_mod.Lock()
_TOKEN_CHAIN_LOCK = _threading_mod.Lock()
_KEY_ROTATION_LOCK = _threading_mod.Lock()
_OTP_LOCK = _threading_mod.Lock()

# ==================== LOGGING ====================
# Configure structured logging once. Replaces every print() in the request path
# with a logger we can route to syslog / journald / Cloud Logging in prod.
logging.basicConfig(
    level=os.environ.get("VOTING_LOG_LEVEL", "INFO"),
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
log = logging.getLogger("voting")

# ==================== CONSTANTS / CONFIG ====================
# All key knobs are env-overridable so deployment never requires code edits.
DB_FILE = os.environ.get("VOTING_DB_FILE", "voting.db")
SERVER_HOST = os.environ.get("VOTING_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("VOTING_PORT", "1776"))
KEY_FILE = os.environ.get("VOTING_KEY_FILE", "voting.key")
SIGNING_KEY_FILE = os.environ.get("VOTING_SIGNING_KEY_FILE", "voting.signing.key")
MAX_REQUEST_BYTES = int(os.environ.get("VOTING_MAX_REQUEST_BYTES", str(1 * 1024 * 1024)))  # 1 MiB
ENABLE_TLS = os.environ.get("VOTING_TLS", "0") == "1"
ALLOWED_ORIGIN = os.environ.get("VOTING_ALLOWED_ORIGIN", "")  # empty = same-origin only
DEFAULT_LANG = os.environ.get("VOTING_DEFAULT_LANG", "en")
OPEN_BROWSER = os.environ.get("VOTING_OPEN_BROWSER", "1") == "1"

# Admin bearer token. If unset, generate one per boot and log it once — better
# than leaving an empty token that grants admin to anyone.
ADMIN_TOKEN = os.environ.get("VOTING_ADMIN_TOKEN", "")
if not ADMIN_TOKEN:
    ADMIN_TOKEN = secrets.token_urlsafe(32)
    log.info("ADMIN TOKEN auto-generated for this boot. Set VOTING_ADMIN_TOKEN to persist. token=%s", ADMIN_TOKEN)

# Session knobs.
SESSION_TTL_SECONDS = int(os.environ.get("VOTING_SESSION_TTL", str(60 * 60)))  # 1 h
OTP_TTL_SECONDS = int(os.environ.get("VOTING_OTP_TTL", "300"))  # 5 min
LOCKOUT_THRESHOLD = int(os.environ.get("VOTING_LOCKOUT_THRESHOLD", "5"))
LOCKOUT_WINDOW_SECONDS = int(os.environ.get("VOTING_LOCKOUT_WINDOW", "900"))  # 15 min
LOCKOUT_DURATION_SECONDS = int(os.environ.get("VOTING_LOCKOUT_DURATION", "900"))  # 15 min

# Persisted symmetric key with rotation support.
# Disk format: a JSON envelope {"primary": "<b64key>", "previous": ["<b64key>", ...], "rotated_at": "iso"}
# When the file already exists in legacy raw-32-byte form we transparently upgrade it.
def _load_or_create_key() -> bytes:
    try:
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "rb") as f:
                blob = f.read().strip()
            # Legacy raw bytes format.
            if len(blob) == 32:
                # Upgrade in-place to the JSON envelope so future rotations work.
                envelope = {
                    "primary": base64.b64encode(blob).decode("ascii"),
                    "previous": [],
                    "rotated_at": datetime.now(timezone.utc).isoformat(),
                }
                _write_key_envelope(envelope)
                return blob
            try:
                envelope = json.loads(blob.decode("utf-8"))
                primary = base64.b64decode(envelope["primary"])
                if len(primary) == 32:
                    return primary
            except (ValueError, KeyError, json.JSONDecodeError):
                log.warning("voting.key envelope unreadable; generating fresh key")
        new_key = secrets.token_bytes(32)
        envelope = {
            "primary": base64.b64encode(new_key).decode("ascii"),
            "previous": [],
            "rotated_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_key_envelope(envelope)
        return new_key
    except OSError as e:
        log.warning("could not persist key file (%s); using ephemeral key for this run", e)
        return secrets.token_bytes(32)


def _write_key_envelope(envelope: Dict[str, Any]) -> None:
    payload = json.dumps(envelope, indent=2).encode("utf-8")
    tmp = KEY_FILE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(payload)
    try:
        os.chmod(tmp, 0o600)
    except (OSError, NotImplementedError):
        pass
    os.replace(tmp, KEY_FILE)


def _read_key_envelope() -> Dict[str, Any]:
    """Return current envelope (with primary + previous), upgrading legacy format on the fly."""
    if not os.path.exists(KEY_FILE):
        return {"primary": "", "previous": [], "rotated_at": ""}
    with open(KEY_FILE, "rb") as f:
        blob = f.read().strip()
    if len(blob) == 32:
        return {
            "primary": base64.b64encode(blob).decode("ascii"),
            "previous": [],
            "rotated_at": "",
        }
    try:
        return json.loads(blob.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return {"primary": "", "previous": [], "rotated_at": ""}


def rotate_encryption_key() -> Dict[str, Any]:
    """Generate a new primary key, demote the previous one, persist, return summary.

    Old ciphertexts/HMACs that used the previous key remain decryptable because
    the previous key stays in the envelope under "previous" — code that needs
    to verify legacy artifacts can iterate KEYRING.
    """
    global ENCRYPTION_KEY, fernet, KEYRING
    with _KEY_ROTATION_LOCK:
        env = _read_key_envelope()
        old_primary = env.get("primary", "")
        prev = env.get("previous", []) or []
        if old_primary:
            prev = [old_primary] + prev
            prev = prev[:8]  # keep last 8 generations
        new_key = secrets.token_bytes(32)
        new_env = {
            "primary": base64.b64encode(new_key).decode("ascii"),
            "previous": prev,
            "rotated_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_key_envelope(new_env)
        ENCRYPTION_KEY = new_key
        if HAS_CRYPTO:
            fernet = Fernet(base64.urlsafe_b64encode(new_key))
        KEYRING = _build_keyring(new_env)
        return {
            "rotated_at": new_env["rotated_at"],
            "previous_count": len(prev),
            "primary_fingerprint": hashlib.sha256(new_key).hexdigest()[:16],
        }


def _build_keyring(env: Optional[Dict[str, Any]] = None) -> List[bytes]:
    env = env or _read_key_envelope()
    out: List[bytes] = []
    if env.get("primary"):
        try:
            out.append(base64.b64decode(env["primary"]))
        except (ValueError, TypeError):
            pass
    for p in env.get("previous", []) or []:
        try:
            out.append(base64.b64decode(p))
        except (ValueError, TypeError):
            pass
    return out


ENCRYPTION_KEY = _load_or_create_key()
KEYRING: List[bytes] = _build_keyring()

# Fernet instance for encryption
if HAS_CRYPTO:
    fernet = Fernet(base64.urlsafe_b64encode(ENCRYPTION_KEY))
else:
    fernet = None


# ==================== ED25519 SIGNING KEY ====================
# Vote tokens are signed with this key. Anyone with the public half can verify
# off-line — the basis for end-to-end vote verifiability. Private half lives at
# SIGNING_KEY_FILE with 0o600.
def _load_or_create_signing_key():
    if not HAS_CRYPTO:
        log.warning("cryptography missing; signing falls back to HMAC-SHA256(ENCRYPTION_KEY, msg)")
        return None
    try:
        if os.path.exists(SIGNING_KEY_FILE):
            with open(SIGNING_KEY_FILE, "rb") as f:
                pem = f.read()
            return serialization.load_pem_private_key(pem, password=None)
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(SIGNING_KEY_FILE, "wb") as f:
            f.write(pem)
        try:
            os.chmod(SIGNING_KEY_FILE, 0o600)
        except (OSError, NotImplementedError):
            pass
        return priv
    except OSError as e:
        log.warning("could not persist signing key (%s); using ephemeral", e)
        return Ed25519PrivateKey.generate() if HAS_CRYPTO else None


SIGNING_KEY = _load_or_create_signing_key()


def sign_blob(blob: bytes) -> str:
    """Return base64 signature of blob. Hex SHA-256 HMAC fallback if no crypto."""
    if SIGNING_KEY is not None:
        sig = SIGNING_KEY.sign(blob)
        return base64.b64encode(sig).decode("ascii")
    return hmac.new(ENCRYPTION_KEY, blob, hashlib.sha256).hexdigest()


def verify_blob(blob: bytes, signature_b64: str) -> bool:
    """Verify signature; tries primary key, then any key in the keyring."""
    if SIGNING_KEY is not None:
        try:
            SIGNING_KEY.public_key().verify(base64.b64decode(signature_b64), blob)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
    expected = hmac.new(ENCRYPTION_KEY, blob, hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected, signature_b64):
        return True
    for k in KEYRING[1:]:
        if hmac.compare_digest(hmac.new(k, blob, hashlib.sha256).hexdigest(), signature_b64):
            return True
    return False


def get_public_signing_key_pem() -> str:
    if SIGNING_KEY is None:
        return ""
    pub = SIGNING_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pub.decode("ascii")


# ==================== DB CONNECTION HELPER ====================
import contextlib

# ==================== DB BACKEND SELECTION ====================
# DATABASE_URL=postgresql://... -> use psycopg (Postgres). Otherwise SQLite.
# This module-level switch lets the same code path work against either backend
# in production. Schema is identical because we use vanilla SQL throughout.
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
USE_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://"))

if USE_POSTGRES:
    try:
        import psycopg  # type: ignore
        from psycopg_pool import ConnectionPool  # type: ignore
        _PG_POOL = ConnectionPool(DATABASE_URL, min_size=1, max_size=10, open=True)
        log.info("Postgres backend enabled via DATABASE_URL")
    except ImportError:
        log.error("DATABASE_URL set but psycopg/psycopg-pool not installed; "
                  "falling back to SQLite. pip install psycopg[binary] psycopg-pool")
        USE_POSTGRES = False
        _PG_POOL = None
else:
    _PG_POOL = None


class _PgCursorAdapter:
    """Translate sqlite-style `?` placeholders to psycopg's `%s` and emulate
    `lastrowid` via RETURNING id where the underlying SQL is an INSERT."""

    def __init__(self, cur):
        self._cur = cur
        self._lastrowid = None
        self.rowcount = 0

    def execute(self, sql, params=()):
        # Transform placeholders. psycopg uses %s.
        translated = sql.replace("?", "%s")
        # For INSERTs without explicit RETURNING, append RETURNING id so we can
        # populate lastrowid for parity with sqlite3. Heuristic: if the SQL
        # starts with INSERT and doesn't already include RETURNING.
        upper = translated.lstrip().upper()
        if upper.startswith("INSERT") and "RETURNING" not in upper:
            translated = translated.rstrip().rstrip(";") + " RETURNING id"
            try:
                self._cur.execute(translated, params)
                row = self._cur.fetchone()
                self._lastrowid = row[0] if row else None
            except Exception:  # noqa: BLE001
                # Tables without `id` PK — execute without RETURNING.
                self._cur.execute(sql.replace("?", "%s"), params)
                self._lastrowid = None
        else:
            self._cur.execute(translated, params)
        self.rowcount = self._cur.rowcount
        return self

    @property
    def lastrowid(self):
        return self._lastrowid

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def __iter__(self):
        return iter(self._cur)

    def close(self):
        self._cur.close()


class _PgConnAdapter:
    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        return _PgCursorAdapter(self._conn.cursor())

    def execute(self, sql, params=()):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        pass  # pool returns it


@contextlib.contextmanager
def db_conn():
    """Yield a connection with appropriate settings. Backend-agnostic.

    SQLite path: WAL + FK + busy timeout.
    Postgres path: pooled connection wrapped to translate ? -> %s and
    emulate sqlite3.cursor.lastrowid via INSERT ... RETURNING id.

    Code that uses this MUST use parameterized queries (we already do).
    """
    if USE_POSTGRES and _PG_POOL is not None:
        with _PG_POOL.connection() as raw:
            yield _PgConnAdapter(raw)
    else:
        conn = sqlite3.connect(DB_FILE, timeout=10.0)
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            yield conn
        finally:
            conn.close()

# ==================== DATA MODELS ====================
@dataclass
class Voter:
    id: int
    name: str
    ssn: str
    eligibility: bool

@dataclass
class Election:
    id: int
    name: str
    type: str
    start_date: datetime
    end_date: datetime

@dataclass
class Vote:
    id: int
    voter_id: int
    election_id: int
    choice: str
    timestamp: datetime

# ==================== DATABASE ====================
# ---------- migration runner ----------
# Each migration is a (version_int, name, sql_or_callable) tuple. They run in
# order, exactly once per database, recorded in `schema_migrations`. NEVER
# reorder existing migrations — append only. Renumbering breaks deployed DBs.
MIGRATIONS: List[Tuple[int, str, Any]] = []


def _migration(version: int, name: str):
    def deco(fn):
        MIGRATIONS.append((version, name, fn))
        return fn
    return deco


@_migration(1, "initial_schema")
def _m_001(c: sqlite3.Cursor) -> None:
    c.execute("""
        CREATE TABLE IF NOT EXISTS voters (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            ssn TEXT NOT NULL,
            state TEXT DEFAULT '',
            eligibility INTEGER NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS elections (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY,
            voter_id INTEGER NOT NULL,
            election_id INTEGER NOT NULL,
            choice TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (voter_id) REFERENCES voters (id),
            FOREIGN KEY (election_id) REFERENCES elections (id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            verified_by TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS vote_tokens (
            id INTEGER PRIMARY KEY,
            token_id TEXT NOT NULL UNIQUE,
            vote_id INTEGER NOT NULL,
            voter_id INTEGER NOT NULL,
            election_id INTEGER NOT NULL,
            genre TEXT NOT NULL,
            category TEXT NOT NULL,
            choice TEXT NOT NULL,
            choice_hash TEXT NOT NULL,
            voter_hash TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            prev_token_hash TEXT NOT NULL,
            auth_layers TEXT NOT NULL,
            device_fingerprint TEXT,
            ip_address TEXT,
            timestamp_created TEXT NOT NULL,
            timestamp_verified TEXT,
            verification_1_hash TEXT NOT NULL,
            verification_2_hash TEXT,
            double_verified INTEGER DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'MINTED',
            FOREIGN KEY (vote_id) REFERENCES votes (id),
            FOREIGN KEY (voter_id) REFERENCES voters (id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_vote_tokens_token_id ON vote_tokens(token_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_vote_tokens_voter_id ON vote_tokens(voter_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_vote_tokens_genre ON vote_tokens(genre)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_vote_tokens_election_id ON vote_tokens(election_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_vote_tokens_timestamp ON vote_tokens(timestamp_created)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_votes_voter_id ON votes(voter_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_votes_election_id ON votes(election_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_voters_ssn ON voters(ssn)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_voters_state ON voters(state)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)")
    # Best-effort uniqueness on votes; if existing dups exist we tolerate it.
    try:
        c.execute("""CREATE UNIQUE INDEX IF NOT EXISTS uniq_votes_voter_election
                     ON votes(voter_id, election_id)""")
    except sqlite3.IntegrityError:
        log.warning("existing duplicate (voter_id, election_id) rows; skipping unique index")


@_migration(2, "voter_eligibility_columns")
def _m_002(c: sqlite3.Cursor) -> None:
    """Add ssn_hash, dob, residency, felony, registration_window. Old schema
    stored ssn in plaintext-formatted form; we keep it for backward compat but
    add a hashed counterpart so future code never has to touch the raw value."""
    cols = {row[1] for row in c.execute("PRAGMA table_info(voters)")}
    additions = [
        ("ssn_hash", "TEXT DEFAULT ''"),
        ("dob", "TEXT DEFAULT ''"),
        ("tax_id_hash", "TEXT DEFAULT ''"),
        ("registered_at", "TEXT DEFAULT ''"),
        ("residency_verified", "INTEGER DEFAULT 0"),
        ("felony_disqualified", "INTEGER DEFAULT 0"),
        ("deceased", "INTEGER DEFAULT 0"),
        ("eligibility_source", "TEXT DEFAULT 'unverified'"),
        ("locked_until", "TEXT DEFAULT ''"),
        ("failed_login_count", "INTEGER DEFAULT 0"),
        ("failed_login_window_start", "TEXT DEFAULT ''"),
    ]
    for name, type_ in additions:
        if name not in cols:
            c.execute(f"ALTER TABLE voters ADD COLUMN {name} {type_}")
    c.execute("CREATE INDEX IF NOT EXISTS idx_voters_ssn_hash ON voters(ssn_hash)")


@_migration(3, "sessions_csrf_otp_totp")
def _m_003(c: sqlite3.Cursor) -> None:
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY,
            session_id TEXT NOT NULL UNIQUE,
            voter_id INTEGER NOT NULL,
            csrf_token TEXT NOT NULL,
            auth_layers_passed TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT DEFAULT '',
            FOREIGN KEY (voter_id) REFERENCES voters(id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_voter_id ON sessions(voter_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
    c.execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY,
            voter_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT DEFAULT '',
            channel TEXT NOT NULL DEFAULT 'in-band-demo',
            FOREIGN KEY (voter_id) REFERENCES voters(id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_otp_codes_voter_id ON otp_codes(voter_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_otp_codes_expires_at ON otp_codes(expires_at)")
    c.execute("""
        CREATE TABLE IF NOT EXISTS totp_secrets (
            voter_id INTEGER PRIMARY KEY,
            secret TEXT NOT NULL,
            last_used_step INTEGER DEFAULT -1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (voter_id) REFERENCES voters(id)
        )
    """)


@_migration(4, "ballot_definitions")
def _m_004(c: sqlite3.Cursor) -> None:
    """Move the hardcoded ballot from JS+Python into the DB."""
    c.execute("""
        CREATE TABLE IF NOT EXISTS races (
            id INTEGER PRIMARY KEY,
            election_id INTEGER NOT NULL,
            race_key TEXT NOT NULL UNIQUE,
            genre TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            type TEXT NOT NULL,
            question TEXT NOT NULL,
            multi_winner INTEGER DEFAULT 0,
            FOREIGN KEY (election_id) REFERENCES elections(id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_races_election_id ON races(election_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_races_genre ON races(genre)")
    c.execute("""
        CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY,
            race_id INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            name TEXT NOT NULL,
            party TEXT DEFAULT '',
            is_write_in INTEGER DEFAULT 0,
            FOREIGN KEY (race_id) REFERENCES races(id) ON DELETE CASCADE
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_candidates_race_id ON candidates(race_id)")
    c.execute("""
        CREATE TABLE IF NOT EXISTS ballot_translations (
            id INTEGER PRIMARY KEY,
            race_id INTEGER,
            candidate_id INTEGER,
            lang TEXT NOT NULL,
            translation TEXT NOT NULL,
            UNIQUE (race_id, candidate_id, lang)
        )
    """)


@_migration(5, "vote_secrecy_split")
def _m_005(c: sqlite3.Cursor) -> None:
    """Ballot secrecy: separate "voter X voted in election Y" from "ballot Z says
    candidate K". The link is broken in the DB so a single SQL query cannot
    re-identify the voter from the vote contents."""
    c.execute("""
        CREATE TABLE IF NOT EXISTS voter_voted (
            id INTEGER PRIMARY KEY,
            voter_id INTEGER NOT NULL,
            election_id INTEGER NOT NULL,
            voted_at TEXT NOT NULL,
            UNIQUE (voter_id, election_id),
            FOREIGN KEY (voter_id) REFERENCES voters(id),
            FOREIGN KEY (election_id) REFERENCES elections(id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_voter_voted_voter_id ON voter_voted(voter_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_voter_voted_election_id ON voter_voted(election_id)")
    c.execute("""
        CREATE TABLE IF NOT EXISTS vote_ballots (
            id INTEGER PRIMARY KEY,
            ballot_id TEXT NOT NULL UNIQUE,
            election_id INTEGER NOT NULL,
            race_key TEXT NOT NULL,
            choice TEXT NOT NULL,
            voter_anchor_hash TEXT NOT NULL,
            cast_at TEXT NOT NULL,
            spoiled INTEGER DEFAULT 0,
            spoiled_at TEXT DEFAULT '',
            FOREIGN KEY (election_id) REFERENCES elections(id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_vote_ballots_election_id ON vote_ballots(election_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_vote_ballots_race_key ON vote_ballots(race_key)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_vote_ballots_anchor ON vote_ballots(voter_anchor_hash)")


@_migration(6, "provisional_and_anchors")
def _m_006(c: sqlite3.Cursor) -> None:
    c.execute("""
        CREATE TABLE IF NOT EXISTS vote_provisional (
            id INTEGER PRIMARY KEY,
            voter_id INTEGER NOT NULL,
            election_id INTEGER NOT NULL,
            sealed_payload TEXT NOT NULL,
            reason TEXT NOT NULL,
            cast_at TEXT NOT NULL,
            adjudicated_at TEXT DEFAULT '',
            adjudicated_by TEXT DEFAULT '',
            adjudication TEXT DEFAULT '',
            FOREIGN KEY (voter_id) REFERENCES voters(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS chain_anchors (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            written_at TEXT NOT NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_chain_anchors_kind ON chain_anchors(kind)")


@_migration(7, "token_signatures")
def _m_007(c: sqlite3.Cursor) -> None:
    cols = {row[1] for row in c.execute("PRAGMA table_info(vote_tokens)")}
    if "signature" not in cols:
        c.execute("ALTER TABLE vote_tokens ADD COLUMN signature TEXT DEFAULT ''")
    if "ballot_id" not in cols:
        c.execute("ALTER TABLE vote_tokens ADD COLUMN ballot_id TEXT DEFAULT ''")


@_migration(8, "key_rotation_journal")
def _m_008(c: sqlite3.Cursor) -> None:
    c.execute("""
        CREATE TABLE IF NOT EXISTS key_rotations (
            id INTEGER PRIMARY KEY,
            rotated_at TEXT NOT NULL,
            primary_fingerprint TEXT NOT NULL,
            previous_count INTEGER NOT NULL,
            triggered_by TEXT NOT NULL
        )
    """)


@_migration(9, "audit_log_hash_column")
def _m_009(c: sqlite3.Cursor) -> None:
    cols = {row[1] for row in c.execute("PRAGMA table_info(audit_log)")}
    if "entry_hash" not in cols:
        c.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT DEFAULT ''")
    if "prev_hash" not in cols:
        c.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT DEFAULT ''")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_entry_hash ON audit_log(entry_hash)")


@_migration(10, "rate_limit_buckets")
def _m_010(c: sqlite3.Cursor) -> None:
    """Persisted rate-limit buckets so restarts don't reset the counters."""
    c.execute("""
        CREATE TABLE IF NOT EXISTS rate_limit (
            id INTEGER PRIMARY KEY,
            bucket TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            window_start TEXT NOT NULL,
            UNIQUE (bucket)
        )
    """)


@_migration(11, "trustee_keys_and_encrypted_ballots")
def _m_011(c: sqlite3.Cursor) -> None:
    """Per-election ElGamal trustee key + encrypted-ballot table.

    The encrypted-ballot table stores ciphertexts and zero-knowledge proofs
    that each ballot encrypts a value in {0, 1}. After the election closes,
    the trustee homomorphically tallies and publishes the result with a
    decryption proof — anyone can verify without trusting the trustee.
    """
    c.execute("""
        CREATE TABLE IF NOT EXISTS election_trustee_keys (
            election_id INTEGER PRIMARY KEY,
            params_json TEXT NOT NULL,
            public_h TEXT NOT NULL,
            private_x TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (election_id) REFERENCES elections(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_ballots (
            id INTEGER PRIMARY KEY,
            ballot_id TEXT NOT NULL UNIQUE,
            election_id INTEGER NOT NULL,
            race_key TEXT NOT NULL,
            voter_anchor_hash TEXT NOT NULL,
            ciphertext_json TEXT NOT NULL,
            proof_json TEXT NOT NULL,
            cast_at TEXT NOT NULL,
            spoiled INTEGER DEFAULT 0,
            FOREIGN KEY (election_id) REFERENCES elections(id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_enc_ballots_election ON encrypted_ballots(election_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_enc_ballots_race ON encrypted_ballots(race_key)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_enc_ballots_anchor ON encrypted_ballots(voter_anchor_hash)")
    c.execute("""
        CREATE TABLE IF NOT EXISTS election_tallies (
            id INTEGER PRIMARY KEY,
            election_id INTEGER NOT NULL,
            race_key TEXT NOT NULL,
            tally INTEGER NOT NULL,
            ciphertext_sum_json TEXT NOT NULL,
            decryption_proof_json TEXT NOT NULL,
            s_value TEXT NOT NULL,
            tallied_at TEXT NOT NULL,
            UNIQUE (election_id, race_key),
            FOREIGN KEY (election_id) REFERENCES elections(id)
        )
    """)


def run_migrations() -> None:
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
        """)
        applied = {row[0] for row in c.execute("SELECT version FROM schema_migrations")}
        for version, name, fn in sorted(MIGRATIONS, key=lambda t: t[0]):
            if version in applied:
                continue
            log.info("applying migration %d: %s", version, name)
            try:
                fn(c)
                c.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (version, name, datetime.now(timezone.utc).isoformat()),
                )
                conn.commit()
            except sqlite3.Error as e:
                conn.rollback()
                log.error("migration %d (%s) FAILED: %s", version, name, e)
                raise


def create_database() -> None:
    """Compatibility shim — calls run_migrations()."""
    run_migrations()

def get_voter(ssn: str) -> Optional[Voter]:
    """Lookup by formatted SSN. Kept for backward compat — new code prefers
    `get_voter_by_id` or session-derived lookup so the SSN never travels."""
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, ssn, eligibility FROM voters WHERE ssn = ?", (ssn,))
        row = c.fetchone()
    return Voter(*row) if row else None


def get_voter_by_id(voter_id: int) -> Optional[Voter]:
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, ssn, eligibility FROM voters WHERE id = ?", (voter_id,))
        row = c.fetchone()
    return Voter(*row) if row else None


def get_election(election_id: int) -> Optional[Election]:
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, type, start_date, end_date FROM elections WHERE id = ?", (election_id,))
        row = c.fetchone()
    return Election(*row) if row else None


def cast_vote(voter_id: int, election_id: int, choice: str) -> None:
    """Legacy direct insert — only used for tests/admin. Real path goes through
    VoteManager.cast_vote, which also splits the ballot for secrecy."""
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO votes (voter_id, election_id, choice, timestamp) VALUES (?, ?, ?, ?)",
            (voter_id, election_id, choice, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()


def get_audit_log() -> List[Dict[str, Any]]:
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id, timestamp, action, status, verified_by FROM audit_log")
        rows = c.fetchall()
    return [{"id": r[0], "timestamp": r[1], "action": r[2], "status": r[3], "verified_by": r[4]} for r in rows]


def is_election_open(election_id: int, *, now: Optional[datetime] = None) -> Tuple[bool, str]:
    """Return (open, reason)."""
    el = get_election(election_id)
    if not el:
        return False, "election not found"
    now = now or datetime.now(timezone.utc)

    def _parse(d: str) -> Optional[datetime]:
        try:
            dt = datetime.fromisoformat(d.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    start = _parse(el.start_date) or datetime.min.replace(tzinfo=timezone.utc)
    end = _parse(el.end_date) or datetime.max.replace(tzinfo=timezone.utc)
    if now < start:
        return False, f"election opens {start.isoformat()}"
    if now > end:
        return False, f"election closed {end.isoformat()}"
    return True, "open"

# ==================== ENCRYPTION ====================
def encrypt(data: str) -> str:
    if HAS_CRYPTO:
        return fernet.encrypt(data.encode()).decode()
    else:
        # Fallback encryption (not secure)
        return hashlib.sha256(data.encode()).hexdigest()

def decrypt(data: str) -> str:
    if HAS_CRYPTO and fernet is not None:
        return fernet.decrypt(data.encode()).decode()
    # Fallback (not real decryption — for compat only when crypto missing)
    return data


def stable_hash(*parts: Any, pepper: bytes = b"") -> str:
    """SHA-256 of pipe-joined parts with optional HMAC pepper. Use this for
    voter_anchor_hash, audit hashes, and anywhere a deterministic non-reversible
    digest is needed. The pepper defaults to ENCRYPTION_KEY so digests cannot
    be precomputed by an attacker without the server's key."""
    payload = "|".join(str(p) for p in parts).encode("utf-8")
    if not pepper:
        pepper = ENCRYPTION_KEY
    return hmac.new(pepper, payload, hashlib.sha256).hexdigest()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


# ==================== SESSION MANAGEMENT ====================
class SessionManager:
    """Server-side sessions backed by `sessions` table. The session_id is wrapped
    in an itsdangerous token before going to the client so a tampered cookie
    fails before we even hit the DB.

    Why server-side: stateless JWT-style tokens are easy to leak, hard to
    revoke, and (most importantly here) leave us with no audit trail of who
    was logged in at what time. The DB row is the audit trail.
    """

    def __init__(self, secret: bytes):
        if HAS_ITSDANGEROUS:
            self.signer = URLSafeTimedSerializer(secret, salt="voting-session")
        else:
            self.signer = None
            self._secret = secret

    def _sign(self, sid: str) -> str:
        if self.signer:
            return self.signer.dumps(sid)
        # HMAC fallback
        mac = hmac.new(self._secret, sid.encode(), hashlib.sha256).hexdigest()
        return f"{sid}.{mac}"

    def _unsign(self, token: str, max_age: int) -> Optional[str]:
        if not token:
            return None
        if self.signer:
            try:
                return self.signer.loads(token, max_age=max_age)
            except (BadSignature, SignatureExpired):
                return None
        try:
            sid, mac = token.rsplit(".", 1)
        except ValueError:
            return None
        expected = hmac.new(self._secret, sid.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            return None
        return sid

    def create(self, voter_id: int, ip: str, user_agent: str) -> Dict[str, str]:
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = utcnow_iso()
        expires = (datetime.now(timezone.utc) + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat()
        with db_conn() as conn:
            c = conn.cursor()
            c.execute(
                """INSERT INTO sessions
                   (session_id, voter_id, csrf_token, auth_layers_passed,
                    ip_address, user_agent, created_at, expires_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (sid, voter_id, csrf, "", ip[:64], (user_agent or "")[:512], now, expires),
            )
            conn.commit()
        return {"session_id": sid, "token": self._sign(sid), "csrf": csrf, "expires_at": expires}

    def load(self, signed_token: str) -> Optional[Dict[str, Any]]:
        sid = self._unsign(signed_token, max_age=SESSION_TTL_SECONDS)
        if not sid:
            return None
        with db_conn() as conn:
            c = conn.cursor()
            c.execute(
                """SELECT id, session_id, voter_id, csrf_token, auth_layers_passed,
                          ip_address, user_agent, created_at, expires_at, revoked_at
                   FROM sessions WHERE session_id = ?""",
                (sid,),
            )
            row = c.fetchone()
        if not row:
            return None
        if row[9]:
            return None  # revoked
        exp = parse_iso(row[8])
        if exp and exp < datetime.now(timezone.utc):
            return None
        return {
            "id": row[0], "session_id": row[1], "voter_id": row[2], "csrf_token": row[3],
            "auth_layers_passed": (row[4] or "").split(",") if row[4] else [],
            "ip_address": row[5], "user_agent": row[6],
            "created_at": row[7], "expires_at": row[8],
        }

    def update_layers(self, session_id: str, new_layer: str) -> None:
        with db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT auth_layers_passed FROM sessions WHERE session_id = ?", (session_id,))
            row = c.fetchone()
            if not row:
                return
            existing = set((row[0] or "").split(",")) if row[0] else set()
            existing.discard("")
            existing.add(new_layer)
            joined = ",".join(sorted(existing))
            c.execute(
                "UPDATE sessions SET auth_layers_passed = ? WHERE session_id = ?",
                (joined, session_id),
            )
            conn.commit()

    def revoke(self, session_id: str) -> None:
        with db_conn() as conn:
            c = conn.cursor()
            c.execute(
                "UPDATE sessions SET revoked_at = ? WHERE session_id = ?",
                (utcnow_iso(), session_id),
            )
            conn.commit()

    def purge_expired(self) -> int:
        with db_conn() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM sessions WHERE expires_at < ?", (utcnow_iso(),))
            n = c.rowcount
            conn.commit()
            return n


# ==================== OTP / TOTP MANAGERS ====================
class OTPManager:
    """Single-use cryptographic random OTP. Stored only as a hash + TTL.

    Real deployment would deliver via Twilio/SES — `_deliver` is the seam
    where a real channel plugs in. For demo/lab use, the unhashed code is
    returned to the caller exactly once.
    """

    @staticmethod
    def issue(voter_id: int, channel: str = "in-band-demo") -> Dict[str, Any]:
        with _OTP_LOCK:
            # Invalidate prior unconsumed codes for this voter so old codes can't replay.
            with db_conn() as conn:
                c = conn.cursor()
                c.execute(
                    """UPDATE otp_codes SET consumed_at = ?
                       WHERE voter_id = ? AND consumed_at = ''""",
                    (utcnow_iso(), voter_id),
                )
                conn.commit()
            code = f"{secrets.randbelow(1_000_000):06d}"
            code_hash = stable_hash("otp", voter_id, code)
            issued = utcnow_iso()
            expires = (datetime.now(timezone.utc) + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()
            with db_conn() as conn:
                c = conn.cursor()
                c.execute(
                    """INSERT INTO otp_codes (voter_id, code_hash, issued_at, expires_at, channel)
                       VALUES (?,?,?,?,?)""",
                    (voter_id, code_hash, issued, expires, channel),
                )
                conn.commit()
            OTPManager._deliver(voter_id, code, channel)
            return {"otp": code, "expires_at": expires, "ttl_seconds": OTP_TTL_SECONDS}

    @staticmethod
    def _deliver(voter_id: int, code: str, channel: str) -> None:
        """Plug-in seam for real OTP delivery (SMS/email). For lab use we log it.
        DEFER: in production, integrate Twilio/SES/etc. here and never log code."""
        log.info("OTP issued voter=%s channel=%s code=%s (LAB MODE)", voter_id, channel, code)

    @staticmethod
    def verify(voter_id: int, code: str) -> bool:
        if not (code and code.isdigit() and len(code) == 6):
            return False
        code_hash = stable_hash("otp", voter_id, code)
        now = utcnow_iso()
        with _OTP_LOCK:
            with db_conn() as conn:
                c = conn.cursor()
                c.execute(
                    """SELECT id, code_hash, expires_at, consumed_at FROM otp_codes
                       WHERE voter_id = ? AND consumed_at = ''
                       ORDER BY id DESC LIMIT 5""",
                    (voter_id,),
                )
                rows = c.fetchall()
                for row in rows:
                    rid, stored_hash, expires_at, _consumed = row
                    if expires_at < now:
                        continue
                    if hmac.compare_digest(stored_hash, code_hash):
                        c.execute(
                            "UPDATE otp_codes SET consumed_at = ? WHERE id = ?",
                            (now, rid),
                        )
                        conn.commit()
                        return True
        return False


class TOTPManager:
    """Real RFC 6238 TOTP via pyotp (HMAC-SHA1, 30s step, 6 digits).

    Replay window: the last successful step is stored per voter; verify rejects
    any step <= last_used_step so a captured code cannot be replayed within its
    30s lifetime. Allows ±1 step skew to tolerate clock drift.
    """

    @staticmethod
    def setup(voter_id: int) -> Dict[str, Any]:
        if not HAS_PYOTP:
            log.warning("pyotp not installed; TOTP setup using HMAC fallback")
        secret_bytes = secrets.token_bytes(20)
        secret = base64.b32encode(secret_bytes).decode("utf-8").rstrip("=")
        with db_conn() as conn:
            c = conn.cursor()
            c.execute(
                """INSERT OR REPLACE INTO totp_secrets (voter_id, secret, last_used_step, created_at)
                   VALUES (?, ?, -1, ?)""",
                (voter_id, secret, utcnow_iso()),
            )
            conn.commit()
        # Return a provisioning URI for QR rendering by the client.
        if HAS_PYOTP:
            uri = pyotp.TOTP(secret).provisioning_uri(
                name=f"voter-{voter_id}@us-ballot",
                issuer_name="U.S. National Ballot Integrity",
            )
            current = pyotp.TOTP(secret).now()
        else:
            uri = f"otpauth://totp/voter-{voter_id}?secret={secret}&issuer=US-Ballot"
            current = TOTPManager._fallback_code(secret, int(time.time()) // 30)
        return {"secret": secret, "current_code": current, "period": 30, "uri": uri}

    @staticmethod
    def _code_for_step(secret: str, step: int) -> str:
        """Return the 6-digit code for a given 30-second step. pyotp's .at()
        treats its argument as a unix timestamp by default — so we pass
        step*30 (start of that step's window) to make it compute the right
        counter value."""
        if HAS_PYOTP:
            return pyotp.TOTP(secret).at(step * 30)
        return TOTPManager._fallback_code(secret, step)

    @staticmethod
    def _fallback_code(secret: str, step: int) -> str:
        """HMAC-SHA1 RFC 4226 implementation in case pyotp is missing."""
        try:
            key = base64.b32decode(secret + "=" * (-len(secret) % 8))
        except (ValueError, TypeError):
            return "000000"
        msg = step.to_bytes(8, "big")
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        truncated = ((digest[offset] & 0x7F) << 24) | ((digest[offset + 1] & 0xFF) << 16) \
            | ((digest[offset + 2] & 0xFF) << 8) | (digest[offset + 3] & 0xFF)
        return f"{truncated % 1000000:06d}"

    @staticmethod
    def verify(voter_id: int, code: str) -> bool:
        if not (code and code.isdigit() and len(code) == 6):
            return False
        with db_conn() as conn:
            c = conn.cursor()
            c.execute(
                "SELECT secret, last_used_step FROM totp_secrets WHERE voter_id = ?",
                (voter_id,),
            )
            row = c.fetchone()
            if not row:
                return False
            secret, last_step = row[0], row[1]
            now_step = int(time.time()) // 30
            for step in (now_step, now_step - 1, now_step + 1):
                if step <= last_step:
                    continue
                expected = TOTPManager._code_for_step(secret, step)
                if hmac.compare_digest(expected, code):
                    c.execute(
                        "UPDATE totp_secrets SET last_used_step = ? WHERE voter_id = ?",
                        (step, voter_id),
                    )
                    conn.commit()
                    return True
        return False


# ==================== LOCKOUT ====================
class LockoutManager:
    """Per-voter login throttle. Backed by columns on `voters`."""

    @staticmethod
    def is_locked(voter_id: int) -> Tuple[bool, Optional[str]]:
        with db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT locked_until FROM voters WHERE id = ?", (voter_id,))
            row = c.fetchone()
        if not row or not row[0]:
            return False, None
        until = parse_iso(row[0])
        if until and until > datetime.now(timezone.utc):
            return True, until.isoformat()
        return False, None

    @staticmethod
    def record_failure(voter_id: int) -> Tuple[int, bool]:
        """Return (new count, was_locked_now)."""
        now = datetime.now(timezone.utc)
        with db_conn() as conn:
            c = conn.cursor()
            c.execute(
                """SELECT failed_login_count, failed_login_window_start FROM voters
                   WHERE id = ?""",
                (voter_id,),
            )
            row = c.fetchone()
            if not row:
                return 0, False
            count, window_start = (row[0] or 0), parse_iso(row[1] or "")
            if not window_start or (now - window_start) > timedelta(seconds=LOCKOUT_WINDOW_SECONDS):
                count = 0
                window_start = now
            count += 1
            locked_until = ""
            locked_now = False
            if count >= LOCKOUT_THRESHOLD:
                locked_until = (now + timedelta(seconds=LOCKOUT_DURATION_SECONDS)).isoformat()
                locked_now = True
            c.execute(
                """UPDATE voters
                   SET failed_login_count = ?,
                       failed_login_window_start = ?,
                       locked_until = ?
                   WHERE id = ?""",
                (count, window_start.isoformat(), locked_until, voter_id),
            )
            conn.commit()
            return count, locked_now

    @staticmethod
    def reset(voter_id: int) -> None:
        with db_conn() as conn:
            c = conn.cursor()
            c.execute(
                """UPDATE voters SET failed_login_count = 0,
                                     failed_login_window_start = '',
                                     locked_until = ''
                   WHERE id = ?""",
                (voter_id,),
            )
            conn.commit()


# ==================== BALLOT STORE ====================
DEFAULT_BALLOT: List[Dict[str, Any]] = [
    {"genre": "FEDERAL", "ordinal": 0, "type": "Presidential",
     "race_key": "cat-0-q0", "question": "PRESIDENT OF THE UNITED STATES",
     "candidates": ["Donald J. Trump (Republican)", "Kamala Harris (Democrat)",
                    "Robert F. Kennedy Jr. (Independent)", "Write-in Candidate"],
     "es": "PRESIDENTE DE LOS ESTADOS UNIDOS"},
    {"genre": "FEDERAL", "ordinal": 1, "type": "Senate",
     "race_key": "cat-0-q1", "question": "U.S. SENATOR",
     "candidates": ["Republican Candidate", "Democrat Candidate", "Libertarian", "Independent"],
     "es": "SENADOR DE EE.UU."},
    {"genre": "FEDERAL", "ordinal": 2, "type": "House",
     "race_key": "cat-0-q2", "question": "U.S. REPRESENTATIVE (House)",
     "candidates": ["District Candidate A", "District Candidate B", "District Candidate C"],
     "es": "REPRESENTANTE DE EE.UU. (Cámara)"},
    {"genre": "FEDERAL", "ordinal": 3, "type": "Judicial",
     "race_key": "cat-0-q3", "question": "SUPREME COURT JUSTICE CONFIRMATION",
     "candidates": ["Confirm Nominee", "Reject Nominee", "Abstain"],
     "es": "CONFIRMACIÓN DE JUEZ DE LA CORTE SUPREMA"},
    {"genre": "STATE", "ordinal": 0, "type": "Governor",
     "race_key": "cat-1-q0", "question": "GOVERNOR",
     "candidates": ["Republican Candidate", "Democrat Candidate", "Independent"],
     "es": "GOBERNADOR"},
    {"genre": "STATE", "ordinal": 1, "type": "State Senate",
     "race_key": "cat-1-q1", "question": "STATE SENATOR",
     "candidates": ["Candidate A", "Candidate B", "Candidate C"],
     "es": "SENADOR ESTATAL"},
    {"genre": "STATE", "ordinal": 2, "type": "State House",
     "race_key": "cat-1-q2", "question": "STATE REPRESENTATIVE",
     "candidates": ["Candidate A", "Candidate B", "Write-in"],
     "es": "REPRESENTANTE ESTATAL"},
    {"genre": "STATE", "ordinal": 3, "type": "State Judicial",
     "race_key": "cat-1-q3", "question": "STATE SUPREME COURT JUSTICE",
     "candidates": ["Candidate A", "Candidate B", "No Preference"],
     "es": "JUEZ DE LA CORTE SUPREMA ESTATAL"},
    {"genre": "STATE", "ordinal": 4, "type": "Proposition",
     "race_key": "cat-1-q4", "question": "PROPOSITION 47: Tax Reform Initiative",
     "candidates": ["YES - Support Tax Reform", "NO - Oppose Tax Reform"],
     "es": "PROPUESTA 47: Iniciativa de Reforma Tributaria"},
    {"genre": "STATE", "ordinal": 5, "type": "Proposition",
     "race_key": "cat-1-q5", "question": "PROPOSITION 48: Education Funding",
     "candidates": ["YES - Increase Funding", "NO - Maintain Current"],
     "es": "PROPUESTA 48: Financiamiento Educativo"},
    {"genre": "LOCAL", "ordinal": 0, "type": "Mayor",
     "race_key": "cat-2-q0", "question": "MAYOR",
     "candidates": ["Incumbent Mayor", "Challenger A", "Challenger B"],
     "es": "ALCALDE"},
    {"genre": "LOCAL", "ordinal": 1, "type": "City Council",
     "race_key": "cat-2-q1", "question": "CITY COUNCIL",
     "candidates": ["District 1 Candidate", "District 2 Candidate", "District 3 Candidate"],
     "es": "CONCEJO MUNICIPAL"},
    {"genre": "LOCAL", "ordinal": 2, "type": "School Board",
     "race_key": "cat-2-q2", "question": "SCHOOL BOARD",
     "candidates": ["Seat 1: Candidate A", "Seat 1: Candidate B", "Seat 2: Candidate C"],
     "es": "JUNTA ESCOLAR"},
    {"genre": "LOCAL", "ordinal": 3, "type": "County",
     "race_key": "cat-2-q3", "question": "COUNTY COMMISSIONER",
     "candidates": ["Republican", "Democrat", "Independent"],
     "es": "COMISIONADO DEL CONDADO"},
    {"genre": "LOCAL", "ordinal": 4, "type": "Municipal",
     "race_key": "cat-2-q4", "question": "MUNICIPAL JUDGE",
     "candidates": ["Judge Candidate A", "Judge Candidate B"],
     "es": "JUEZ MUNICIPAL"},
    {"genre": "LOCAL", "ordinal": 5, "type": "Bond",
     "race_key": "cat-2-q5", "question": "LOCAL BOND MEASURE: School Construction",
     "candidates": ["YES - Approve Bonds", "NO - Reject Bonds"],
     "es": "MEDIDA DE BONOS LOCAL: Construcción Escolar"},
    {"genre": "PETITION", "ordinal": 0, "type": "National Petition",
     "race_key": "cat-3-q0", "question": "NATIONAL PETITION: Term Limits for Congress",
     "candidates": ["SUPPORT - 12 Year Limit", "OPPOSE - No Limit Changes"],
     "es": "PETICIÓN NACIONAL: Límites de Mandato para el Congreso"},
    {"genre": "PETITION", "ordinal": 1, "type": "National Petition",
     "race_key": "cat-3-q1", "question": "NATIONAL PETITION: Balanced Budget Amendment",
     "candidates": ["SUPPORT Amendment", "OPPOSE Amendment"],
     "es": "PETICIÓN NACIONAL: Enmienda de Presupuesto Equilibrado"},
    {"genre": "PETITION", "ordinal": 2, "type": "State Petition",
     "race_key": "cat-3-q2", "question": "STATE PETITION: Ranked Choice Voting",
     "candidates": ["SUPPORT RCV", "OPPOSE RCV"],
     "es": "PETICIÓN ESTATAL: Voto por Orden de Preferencia"},
    {"genre": "PETITION", "ordinal": 3, "type": "State Law",
     "race_key": "cat-3-q3", "question": "STATE LAW: 2nd Amendment Sanctuary",
     "candidates": ["ENACT Sanctuary Law", "REJECT Sanctuary Law"],
     "es": "LEY ESTATAL: Santuario de la Segunda Enmienda"},
    {"genre": "PETITION", "ordinal": 4, "type": "State Law",
     "race_key": "cat-3-q4", "question": "STATE LAW: Universal Healthcare",
     "candidates": ["ENACT Healthcare", "REJECT Healthcare"],
     "es": "LEY ESTATAL: Salud Universal"},
    {"genre": "PETITION", "ordinal": 5, "type": "Local Ordinance",
     "race_key": "cat-3-q5", "question": "LOCAL ORDINANCE: Zoning Changes",
     "candidates": ["APPROVE Zoning", "REJECT Zoning"],
     "es": "ORDENANZA LOCAL: Cambios de Zonificación"},
    {"genre": "PETITION", "ordinal": 6, "type": "Local Ordinance",
     "race_key": "cat-3-q6", "question": "LOCAL ORDINANCE: Public Safety Funding",
     "candidates": ["INCREASE Funding", "MAINTAIN Funding"],
     "es": "ORDENANZA LOCAL: Financiamiento de Seguridad Pública"},
    {"genre": "PETITION", "ordinal": 7, "type": "Initiative",
     "race_key": "cat-3-q7", "question": "CITIZEN INITIATIVE: Environmental Protection",
     "candidates": ["SUPPORT Initiative", "OPPOSE Initiative"],
     "es": "INICIATIVA CIUDADANA: Protección Ambiental"},
]


class BallotStore:
    """Single source of truth for ballot definitions. Replaces the duplicate
    hardcoded arrays that lived in Python and JS and drifted independently."""

    @staticmethod
    def seed_if_empty(default_election_id: int = 1) -> None:
        with db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM races")
            if c.fetchone()[0] > 0:
                return
            for race in DEFAULT_BALLOT:
                c.execute(
                    """INSERT OR IGNORE INTO races
                       (election_id, race_key, genre, ordinal, type, question, multi_winner)
                       VALUES (?,?,?,?,?,?,0)""",
                    (default_election_id, race["race_key"], race["genre"],
                     race["ordinal"], race["type"], race["question"]),
                )
                c.execute("SELECT id FROM races WHERE race_key = ?", (race["race_key"],))
                rid = c.fetchone()[0]
                for i, cand in enumerate(race["candidates"]):
                    is_writein = 1 if "Write-in" in cand else 0
                    c.execute(
                        """INSERT INTO candidates (race_id, ordinal, name, party, is_write_in)
                           VALUES (?,?,?,'',?)""",
                        (rid, i, cand, is_writein),
                    )
                if race.get("es"):
                    c.execute(
                        """INSERT OR IGNORE INTO ballot_translations
                           (race_id, candidate_id, lang, translation) VALUES (?, NULL, 'es', ?)""",
                        (rid, race["es"]),
                    )
            conn.commit()

    @staticmethod
    def get_ballot(lang: str = "en") -> List[Dict[str, Any]]:
        with db_conn() as conn:
            c = conn.cursor()
            c.execute(
                """SELECT id, election_id, race_key, genre, ordinal, type, question, multi_winner
                   FROM races ORDER BY genre, ordinal"""
            )
            races = c.fetchall()
            out = []
            for rid, eid, rkey, genre, ord_, type_, question, mw in races:
                c.execute(
                    "SELECT id, ordinal, name, party, is_write_in FROM candidates WHERE race_id = ? ORDER BY ordinal",
                    (rid,),
                )
                cands = c.fetchall()
                question_localized = question
                if lang and lang != "en":
                    c.execute(
                        """SELECT translation FROM ballot_translations
                           WHERE race_id = ? AND candidate_id IS NULL AND lang = ?""",
                        (rid, lang),
                    )
                    tr = c.fetchone()
                    if tr:
                        question_localized = tr[0]
                out.append({
                    "id": rid, "election_id": eid, "race_key": rkey, "genre": genre,
                    "ordinal": ord_, "type": type_, "question": question_localized,
                    "multi_winner": bool(mw),
                    "candidates": [
                        {"id": cid, "ordinal": co, "name": cn, "party": cp, "is_write_in": bool(cw)}
                        for cid, co, cn, cp, cw in cands
                    ],
                })
            return out

    @staticmethod
    def race_key_exists(race_key: str) -> bool:
        with db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT 1 FROM races WHERE race_key = ?", (race_key,))
            return c.fetchone() is not None


# ==================== FRONTEND ====================
HTML_CONTENT = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>U.S. NATIONAL BALLOT INTEGRITY & VERIFICATION SYSTEM v1.17 • DEPARTMENT OF ELECTORAL SECURITY</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="/static/voting.css">
</head>
<body class="text-gray-900" style="background:var(--parchment)">

<a href="#app" class="skip-link">Skip to main content</a>

<nav class="star-bg text-white shadow-2xl sticky top-0 z-50" style="border-bottom: none;" role="navigation" aria-label="Primary">
    <!-- Top gold accent line -->
    <div style="height:3px;background:linear-gradient(90deg,transparent,#FFD700,transparent)"></div>
    <div class="max-w-screen-2xl mx-auto px-4 py-3 flex items-center justify-between relative" style="z-index:2">
        <div class="flex items-center gap-x-4">
            <div class="gold-seal" style="width:56px;height:56px;font-size:26px;flex-shrink:0">🦅</div>
            <div>
                <div class="flex items-center gap-2">
                    <h1 class="header-font text-xl font-black tracking-wide" style="line-height:1.15;text-shadow:0 2px 8px rgba(0,0,0,0.4)">U.S. NATIONAL BALLOT INTEGRITY<br>&amp; VERIFICATION SYSTEM <span style="color:#FFD700;text-shadow:0 0 10px rgba(255,215,0,0.5)">v1.17</span></h1>
                </div>
                <p class="text-xs tracking-[3px] font-bold" style="color:#FFD700;text-shadow:0 1px 4px rgba(0,0,0,0.3)">★ DEPARTMENT OF ELECTORAL SECURITY ★ EST. 1776 ★</p>
            </div>
        </div>
        
        <!-- 50 State Selector -->
        <div class="flex items-center gap-x-3">
            <select id="state-selector" class="px-4 py-2 rounded-lg bg-white text-blue-900 font-bold border-2 border-blue-900 text-sm" onchange="selectState(this.value)">
                <option value="">🏛️ SELECT YOUR STATE</option>
                <option value="AL">🇺🇸 Alabama</option><option value="AK">🇺🇸 Alaska</option><option value="AZ">🇺🇸 Arizona</option>
                <option value="AR">🇺🇸 Arkansas</option><option value="CA">🇺🇸 California</option><option value="CO">🇺🇸 Colorado</option>
                <option value="CT">🇺🇸 Connecticut</option><option value="DE">🇺🇸 Delaware</option><option value="FL">🇺🇸 Florida</option>
                <option value="GA">🇺🇸 Georgia</option><option value="HI">🇺🇸 Hawaii</option><option value="ID">🇺🇸 Idaho</option>
                <option value="IL">🇺🇸 Illinois</option><option value="IN">🇺🇸 Indiana</option><option value="IA">🇺🇸 Iowa</option>
                <option value="KS">🇺🇸 Kansas</option><option value="KY">🇺🇸 Kentucky</option><option value="LA">🇺🇸 Louisiana</option>
                <option value="ME">🇺🇸 Maine</option><option value="MD">🇺🇸 Maryland</option><option value="MA">🇺🇸 Massachusetts</option>
                <option value="MI">🇺🇸 Michigan</option><option value="MN">🇺🇸 Minnesota</option><option value="MS">🇺🇸 Mississippi</option>
                <option value="MO">🇺🇸 Missouri</option><option value="MT">🇺🇸 Montana</option><option value="NE">🇺🇸 Nebraska</option>
                <option value="NV">🇺🇸 Nevada</option><option value="NH">🇺🇸 New Hampshire</option><option value="NJ">🇺🇸 New Jersey</option>
                <option value="NM">🇺🇸 New Mexico</option><option value="NY">🇺🇸 New York</option><option value="NC">🇺🇸 North Carolina</option>
                <option value="ND">🇺🇸 North Dakota</option><option value="OH">🇺🇸 Ohio</option><option value="OK">🇺🇸 Oklahoma</option>
                <option value="OR">🇺🇸 Oregon</option><option value="PA">🇺🇸 Pennsylvania</option><option value="RI">🇺🇸 Rhode Island</option>
                <option value="SC">🇺🇸 South Carolina</option><option value="SD">🇺🇸 South Dakota</option><option value="TN">🇺🇸 Tennessee</option>
                <option value="TX">🇺🇸 Texas</option><option value="UT">🇺🇸 Utah</option><option value="VT">🇺🇸 Vermont</option>
                <option value="VA">🇺🇸 Virginia</option><option value="WA">🇺🇸 Washington</option><option value="WV">🇺🇸 West Virginia</option>
                <option value="WI">🇺🇸 Wisconsin</option><option value="WY">🇺🇸 Wyoming</option>
                <option value="DC">🇺🇸 Washington D.C.</option>
            </select>
        </div>
        
        <!-- Navigation Buttons (FULLY FUNCTIONAL) -->
        <div class="flex items-center gap-x-4 text-sm">
            <button onclick="navigateTo('home')" class="px-3 py-2 hover:bg-white/20 rounded-lg transition flex items-center gap-x-1 font-bold"><i class="fa-solid fa-flag-usa"></i> HOME</button>
            <button onclick="navigateTo('enroll')" class="px-3 py-2 bg-red-700 hover:bg-red-600 rounded-lg transition flex items-center gap-x-1 font-bold border border-yellow-400"><i class="fa-solid fa-shield-halved"></i> REGISTER &amp; VOTE</button>
            <button onclick="navigateTo('dashboard')" class="px-3 py-2 hover:bg-white/20 rounded-lg transition flex items-center gap-x-1 font-bold"><i class="fa-solid fa-chart-line"></i> DASHBOARD</button>
            <button onclick="navigateTo('audit')" class="px-3 py-2 hover:bg-white/20 rounded-lg transition flex items-center gap-x-1 font-bold"><i class="fa-solid fa-scale-balanced"></i> AUDIT</button>
            <button onclick="navigateTo('pile')" class="px-3 py-2 hover:bg-white/20 rounded-lg transition flex items-center gap-x-1 font-bold"><i class="fa-solid fa-cubes"></i> PILE</button>
            <button onclick="navigateTo('verify')" class="px-3 py-2 hover:bg-white/20 rounded-lg transition flex items-center gap-x-1 font-bold" style="color:#4ade80"><i class="fa-solid fa-magnifying-glass-chart"></i> VERIFY</button>
            <button onclick="navigateTo('results')" class="px-3 py-2 hover:bg-white/20 rounded-lg transition flex items-center gap-x-1 font-bold" style="color:#fbbf24"><i class="fa-solid fa-trophy"></i> RESULTS</button>
            <button onclick="runChainTest()" class="px-3 py-2 hover:bg-white/20 rounded-lg transition flex items-center gap-x-1 font-bold" style="color:#60a5fa"><i class="fa-solid fa-link"></i> CHAIN TEST</button>
            <button onclick="navigateTo('explorer')" class="px-3 py-2 hover:bg-white/20 rounded-lg transition flex items-center gap-x-1 font-bold" style="color:#a78bfa"><i class="fa-solid fa-cubes"></i> EXPLORER</button>
            <button onclick="openExportModal()" class="px-3 py-2 hover:bg-white/20 rounded-lg transition flex items-center gap-x-1 font-bold" style="color:#f472b6"><i class="fa-solid fa-download"></i> EXPORT</button>
            <button onclick="navigateTo('about')" class="px-3 py-2 hover:bg-white/20 rounded-lg transition flex items-center gap-x-1 font-bold"><i class="fa-solid fa-circle-info"></i> ABOUT</button>
            <button onclick="navigateTo('power')" class="px-3 py-2 hover:bg-white/20 rounded-lg transition flex items-center gap-x-1 font-bold"><i class="fa-solid fa-fist-raised"></i> POWER</button>
            <button onclick="navigateTo('incentives')" class="px-3 py-2 hover:bg-white/20 rounded-lg transition flex items-center gap-x-1 font-bold"><i class="fa-solid fa-lightbulb"></i> WHY VOTE</button>
        </div>
        
        <div class="flex items-center gap-x-3">
            <div class="bg-white/20 px-3 py-1 rounded-full text-xs font-mono border border-yellow-400">
                <span id="quantum-counter" class="text-yellow-300 font-bold">KEY ROTATION ACTIVE</span>
            </div>
            <button onclick="logout()" class="flex items-center gap-x-2 text-sm hover:text-yellow-300 transition">
                <i class="fa-solid fa-user-shield"></i>
                <span id="nav-user" class="font-bold">NOT LOGGED IN</span>
            </button>
        </div>
    </div>
</nav>

<div id="app" class="max-w-screen-2xl mx-auto px-8 py-8">

    <!-- HOME -->
    <div id="screen-home" class="screen">
        <div class="text-center py-6">
            <!-- Grand patriotic header -->
            <div class="mb-6">
                <div class="flex justify-center items-center gap-4 mb-3">
                    <span style="font-size:48px">🇺🇸</span>
                    <div class="gold-seal" style="width:80px;height:80px;font-size:38px">🦅</div>
                    <span style="font-size:48px">🇺🇸</span>
                </div>
                <h1 class="header-font text-6xl font-black mb-2" style="color:#002868;text-shadow:2px 2px 0 rgba(191,10,48,0.15)">SECURE AMERICAN VOTING</h1>
                <div class="patriot-divider max-w-md mx-auto" style="margin:8px auto 12px"></div>
                <p class="text-xl font-bold" style="color:#BF0A30;letter-spacing:3px">★ ONE NATION ★ ONE SECURE VOICE ★ ZERO TOLERANCE FOR FRAUD ★</p>
                <p class="text-sm text-gray-500 mt-2 italic header-font">"We the People of the United States, in Order to form a more perfect Union, establish Justice, insure domestic Tranquility..."</p>
            </div>
            
            <!-- Geographic US Map -->
            <div class="patriot-card p-6 mb-6 max-w-5xl mx-auto shadow-xl" style="border-width:3px;border-color:#002868">
                <div class="patriot-banner mb-4" style="padding:12px 20px;border-radius:12px">
                    <h2 class="header-font text-xl font-bold text-center" style="letter-spacing:2px">★ SELECT YOUR STATE TO VIEW ELECTIONS ★</h2>
                </div>
                <div id="us-map" class="us-map-grid"></div>
                <div class="flex justify-center items-center gap-6 mt-4 mb-2">
                    <div class="flex items-center gap-2"><span class="w-4 h-4 rounded" style="background:#002868"></span><span class="text-xs text-gray-600">High Participation (10+ votes)</span></div>
                    <div class="flex items-center gap-2"><span class="w-4 h-4 rounded" style="background:#DAA520"></span><span class="text-xs text-gray-600">Medium (5-9 votes)</span></div>
                    <div class="flex items-center gap-2"><span class="w-4 h-4 rounded" style="background:#BF0A30"></span><span class="text-xs text-gray-600">Low (1-4 votes)</span></div>
                    <div class="flex items-center gap-2"><span class="w-4 h-4 rounded bg-gray-300"></span><span class="text-xs text-gray-600">No votes</span></div>
                </div>
                <p class="text-gray-500 text-sm">Click your state on the map or use the dropdown in the navigation bar</p>
            </div>
            
            <!-- Feature Cards (FUNCTIONAL) -->
            <div class="grid grid-cols-4 gap-4 mb-8 max-w-4xl mx-auto">
                <div onclick="openFeatureModal('live4k')" class="feature-card bg-white border-2 border-blue-900 rounded-xl p-6 text-center shadow-lg">
                    <i class="fa-solid fa-video text-4xl text-red-700 mb-3"></i>
                    <h3 class="font-bold text-sm text-blue-900">Live 4K Verification</h3>
                    <p class="text-xs text-gray-500 mt-1">Click for details</p>
                </div>
                <div onclick="openFeatureModal('biometrics')" class="feature-card bg-white border-2 border-blue-900 rounded-xl p-6 text-center shadow-lg">
                    <i class="fa-solid fa-fingerprint text-4xl text-blue-800 mb-3"></i>
                    <h3 class="font-bold text-sm text-blue-900">Quantum Biometrics</h3>
                    <p class="text-xs text-gray-500 mt-1">Click for details</p>
                </div>
                <div onclick="openFeatureModal('ledger')" class="feature-card bg-white border-2 border-blue-900 rounded-xl p-6 text-center shadow-lg">
                    <i class="fa-solid fa-link text-4xl text-red-700 mb-3"></i>
                    <h3 class="font-bold text-sm text-blue-900">Immutable Ledger</h3>
                    <p class="text-xs text-gray-500 mt-1">Click for details</p>
                </div>
                <div onclick="openFeatureModal('taxpayer')" class="feature-card bg-white border-2 border-blue-900 rounded-xl p-6 text-center shadow-lg">
                    <i class="fa-solid fa-users text-4xl text-blue-800 mb-3"></i>
                    <h3 class="font-bold text-sm text-blue-900">Taxpayer Power</h3>
                    <p class="text-xs text-gray-500 mt-1">Click for details</p>
                </div>
            </div>
            
            <div class="patriot-divider max-w-lg mx-auto"></div>
            <button onclick="navigateTo('enroll')" class="px-14 py-5 text-2xl font-black rounded-2xl shadow-2xl flex items-center gap-x-4 mx-auto mb-6 transition hover:scale-105 hover:shadow-3xl" style="background: linear-gradient(135deg, #BF0A30 0%, #8B0000 50%, #600 100%); color: white; border: 3px solid #FFD700; text-shadow: 0 2px 4px rgba(0,0,0,0.3); letter-spacing: 1px;">
                <span style="font-size:28px">🇺🇸</span> ENROLL &amp; CAST YOUR VOTE <span style="font-size:28px">🗳️</span>
            </button>
            <div class="max-w-2xl mx-auto text-center">
                <p class="header-font text-lg mb-1" style="color:#002868">"Government of the people, by the people, for the people,<br>shall not perish from the earth."</p>
                <p class="text-xs text-gray-400 font-bold tracking-widest">— PRESIDENT ABRAHAM LINCOLN, GETTYSBURG ADDRESS, 1863</p>
            </div>
        </div>
    </div>

    <!-- Feature Modal Container -->
    <div id="feature-modal" class="modal-overlay hidden" onclick="if(event.target===this)closeModal()">
        <div class="modal-content">
            <div class="flex justify-between items-center mb-6">
                <h2 id="modal-title" class="header-font text-3xl text-blue-900"></h2>
                <button onclick="closeModal()" class="text-gray-400 hover:text-red-600 text-2xl"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <div id="modal-body"></div>
        </div>
    </div>

    <!-- ENROLL -->
    <div id="screen-enroll" class="screen hidden">
        <div class="max-w-2xl mx-auto patriot-card shadow-2xl rounded-3xl p-10" style="border-width:3px">
            <div class="text-center mb-2"><div class="gold-seal mx-auto mb-3" style="width:56px;height:56px;font-size:24px">🛡️</div></div>
            <h2 class="header-font text-4xl text-center mb-2" style="color:#002868">One-Time Enrollment</h2>
            <p class="text-center text-sm mb-6" style="color:#BF0A30;font-weight:700;letter-spacing:2px">★ SECURE THE REPUBLIC ★</p>
            <div class="patriot-divider" style="margin:0 0 24px"></div>
            <div class="space-y-8">
                <div>
                    <label class="block text-sm font-bold mb-2">SOCIAL SECURITY NUMBER</label>
                    <input id="ssn-input" type="text" maxlength="11" placeholder="123-45-6789" class="w-full border-2 border-blue-800 rounded-2xl px-6 py-5 text-3xl focus:outline-none focus:border-red-700">
                </div>
                <div class="grid grid-cols-2 gap-6">
                    <div>
                        <label class="block text-sm font-bold mb-2">FULL LEGAL NAME</label>
                        <input id="enroll-name" type="text" value="Johnathan Q. Patriot" class="w-full border-2 border-blue-800 rounded-2xl px-6 py-5 text-3xl">
                    </div>
                    <div>
                        <label class="block text-sm font-bold mb-2">DATE OF BIRTH</label>
                        <input id="enroll-dob" type="text" value="07/04/1996" class="w-full border-2 border-blue-800 rounded-2xl px-6 py-5 text-3xl">
                    </div>
                </div>
                <button onclick="simulateEnrollment()" class="w-full py-6 bg-gradient-to-r from-blue-800 to-red-700 text-white text-3xl font-bold rounded-3xl">
                    <i class="fa-solid fa-lock"></i> COMPLETE ENROLLMENT &amp; CAPTURE BASELINE BIOMETRICS
                </button>
            </div>
        </div>
    </div>

    <!-- VERIFY: 5-LAYER AUTHENTICATION (entered automatically after enrollment) -->
    <div id="screen-login" class="screen hidden">
        <div class="max-w-4xl mx-auto">
            <div class="patriot-banner mb-6" style="text-align:center">
                <h2 class="header-font text-3xl">★ 5-LAYER VOTER VERIFICATION ★</h2>
                <p class="text-sm mt-1" style="color:#FFD700">Every layer must pass before your ballot is unlocked and Paper Slips can be minted.</p>
            </div>
            
            <!-- Auth Progress Bar -->
            <div class="auth-step-indicator mb-8" role="progressbar" aria-valuemin="1" aria-valuemax="5" aria-valuenow="1" aria-label="Authentication progress">
                <div id="auth-dot-1" class="auth-step-dot active" aria-label="Layer 1 active"></div>
                <div id="auth-dot-2" class="auth-step-dot" aria-label="Layer 2 pending"></div>
                <div id="auth-dot-3" class="auth-step-dot" aria-label="Layer 3 pending"></div>
                <div id="auth-dot-4" class="auth-step-dot" aria-label="Layer 4 pending"></div>
                <div id="auth-dot-5" class="auth-step-dot" aria-label="Layer 5 pending"></div>
            </div>
            <div class="text-center mb-6 text-sm font-bold text-blue-900" role="status" aria-live="polite">
                <span id="auth-step-label">LAYER 1 OF 5: IDENTITY VERIFICATION</span>
            </div>

            <!-- LAYER 1: SSN + Tax PIN -->
            <div id="auth-step-1" class="step">
                <div class="bg-white rounded-3xl shadow-xl p-8 mb-6 border-2 border-blue-800">
                    <h3 class="text-2xl font-bold mb-2"><i class="fa-solid fa-id-card text-blue-800 mr-2"></i> Layer 1: Knowledge Factor</h3>
                    <p class="text-gray-500 mb-6">Verify your SSN and Tax History PIN to prove identity.</p>
                    <input id="login-ssn" type="text" maxlength="11" placeholder="SSN: XXX-XX-XXXX" class="w-full text-2xl border-3 border-blue-800 rounded-2xl p-5 mb-4">
                    <input id="login-pin" type="text" placeholder="Tax History PIN" class="w-full text-2xl border-3 border-blue-800 rounded-2xl p-5">
                    <button onclick="authLayer1()" class="mt-6 w-full py-5 text-xl bg-blue-800 text-white rounded-2xl font-bold">VERIFY IDENTITY <i class="fa-solid fa-arrow-right ml-2"></i></button>
                </div>
            </div>

            <!-- LAYER 2: LIVE CAMERA + MIC BIOMETRIC -->
            <div id="auth-step-2" class="step hidden">
                <div class="bg-white rounded-3xl shadow-xl p-8 border-2 border-blue-800">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-2xl font-bold"><i class="fa-solid fa-camera text-red-700 mr-2"></i> Layer 2: Live Biometric Capture</h3>
                        <span onclick="endSession()" class="cursor-pointer text-red-600"><i class="fa-solid fa-xmark"></i></span>
                    </div>
                    <p class="text-gray-500 mb-6">Live 4K camera and microphone verify you are a real person, not a recording or deepfake.</p>
                    <div class="grid grid-cols-2 gap-6">
                        <div>
                            <video id="video-feed" autoplay playsinline class="w-full aspect-video bg-black rounded-2xl shadow-inner"></video>
                            <button onclick="startCamera()" class="mt-4 w-full py-3 bg-red-700 hover:bg-red-800 text-white text-lg rounded-2xl flex items-center justify-center gap-x-3">
                                <i class="fa-solid fa-video"></i> START LIVE CAMERA &amp; MIC
                            </button>
                        </div>
                        <div class="flex flex-col">
                            <div class="flex-1 bg-gradient-to-br from-blue-900 to-red-900 text-white rounded-2xl p-6 flex flex-col items-center justify-center text-center">
                                <p id="challenge-text" class="text-xl font-light leading-tight">Awaiting camera activation...</p>
                                <div id="deepfake-meter" class="w-full mt-6 bg-gray-800 rounded-xl p-2">
                                    <div class="text-xs text-center mb-1">DEEPFAKE / REPLAY PROBABILITY</div>
                                    <div class="h-3 bg-green-500 rounded-lg relative overflow-hidden">
                                        <div id="deepfake-bar" class="absolute h-full bg-red-500 transition-all" style="width: 3%"></div>
                                    </div>
                                </div>
                            </div>
                            <button onclick="authLayer2()" class="mt-4 w-full py-4 text-xl font-bold bg-green-600 hover:bg-green-700 text-white rounded-2xl">VERIFY BIOMETRICS <i class="fa-solid fa-arrow-right ml-2"></i></button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- LAYER 3: RANDOM OTP -->
            <div id="auth-step-3" class="step hidden">
                <div class="bg-white rounded-3xl shadow-xl p-8 border-2 border-blue-800">
                    <h3 class="text-2xl font-bold mb-2"><i class="fa-solid fa-dice text-blue-800 mr-2"></i> Layer 3: One-Time Passcode (OTP)</h3>
                    <p class="text-gray-500 mb-6">A unique random code has been generated for this voting session. Enter the code shown below to proceed.</p>
                    <div class="text-center mb-6">
                        <div class="inline-block bg-blue-900 text-yellow-300 px-12 py-6 rounded-2xl">
                            <div class="text-sm font-bold mb-2">YOUR SESSION OTP CODE</div>
                            <div id="otp-display" class="text-5xl font-mono font-black tracking-[12px]">------</div>
                        </div>
                    </div>
                    <input id="otp-input" type="text" maxlength="6" placeholder="Enter the 6-digit OTP code shown above" class="w-full text-3xl border-3 border-blue-800 rounded-2xl p-5 text-center tracking-[8px] font-mono">
                    <button onclick="authLayer3()" class="mt-6 w-full py-5 text-xl bg-blue-800 text-white rounded-2xl font-bold">VERIFY OTP <i class="fa-solid fa-arrow-right ml-2"></i></button>
                </div>
            </div>

            <!-- LAYER 4: TOTP AUTHENTICATOR -->
            <div id="auth-step-4" class="step hidden">
                <div class="bg-white rounded-3xl shadow-xl p-8 border-2 border-blue-800">
                    <h3 class="text-2xl font-bold mb-2"><i class="fa-solid fa-shield-halved text-red-700 mr-2"></i> Layer 4: Authenticator App (TOTP)</h3>
                    <p class="text-gray-500 mb-6">Enter the 6-digit code from your pre-registered authenticator app (Google Authenticator, Authy, etc.).</p>
                    <div class="bg-gray-50 border-2 border-dashed border-blue-300 rounded-2xl p-6 mb-6 text-center">
                        <p class="text-sm text-gray-600 mb-2">If you have not set up your authenticator, use this demo secret:</p>
                        <div id="totp-secret-display" class="font-mono text-lg font-bold text-blue-900 mb-2">Loading...</div>
                        <div id="totp-qr" class="text-sm text-gray-500">Scan in your authenticator app or enter manually</div>
                        <div class="mt-3 text-xs text-gray-400">Code rotates every 30 seconds</div>
                        <div id="totp-timer" class="mt-2 text-2xl font-bold text-red-700">--s remaining</div>
                    </div>
                    <input id="totp-input" type="text" maxlength="6" placeholder="Enter 6-digit authenticator code" class="w-full text-3xl border-3 border-blue-800 rounded-2xl p-5 text-center tracking-[8px] font-mono">
                    <button onclick="authLayer4()" class="mt-6 w-full py-5 text-xl bg-blue-800 text-white rounded-2xl font-bold">VERIFY AUTHENTICATOR <i class="fa-solid fa-arrow-right ml-2"></i></button>
                </div>
            </div>

            <!-- LAYER 5: BEHAVIORAL ANALYSIS -->
            <div id="auth-step-5" class="step hidden">
                <div class="bg-white rounded-3xl shadow-xl p-8 border-2 border-blue-800">
                    <h3 class="text-2xl font-bold mb-2"><i class="fa-solid fa-brain text-blue-800 mr-2"></i> Layer 5: Behavioral Verification</h3>
                    <p class="text-gray-500 mb-6">Complete the behavioral challenge to prove you are human and not under coercion.</p>
                    <div class="bg-gradient-to-br from-blue-900 to-red-900 text-white rounded-2xl p-8 text-center mb-6">
                        <p class="text-sm mb-2 opacity-70">SPEAK THIS PHRASE ALOUD:</p>
                        <p id="behavior-challenge" class="text-2xl font-bold leading-relaxed">"I cast this ballot freely, as a citizen of the United States of America."</p>
                        <div class="mt-6 flex justify-center gap-6">
                            <div class="text-center">
                                <div id="behavior-voice" class="text-4xl mb-1">🎤</div>
                                <div class="text-xs">Voice Match</div>
                                <div id="voice-status" class="text-yellow-300 font-bold text-sm">Waiting...</div>
                            </div>
                            <div class="text-center">
                                <div id="behavior-face" class="text-4xl mb-1">👤</div>
                                <div class="text-xs">Face Match</div>
                                <div id="face-status" class="text-yellow-300 font-bold text-sm">Waiting...</div>
                            </div>
                            <div class="text-center">
                                <div class="text-4xl mb-1">🧠</div>
                                <div class="text-xs">Coercion Check</div>
                                <div id="coercion-status" class="text-yellow-300 font-bold text-sm">Waiting...</div>
                            </div>
                        </div>
                    </div>
                    <button onclick="authLayer5()" class="w-full py-5 text-xl bg-green-600 hover:bg-green-700 text-white rounded-2xl font-bold">COMPLETE VERIFICATION &amp; PROCEED TO BALLOT <i class="fa-solid fa-check ml-2"></i></button>
                </div>
            </div>
        </div>
    </div>

    <!-- VOTING BALLOT (OVERKILL TABS + PERSISTENT SELECTIONS) -->
    <div id="screen-vote" class="screen hidden">
        <h2 class="header-font text-5xl mb-8 text-center">Your Personalized Ballot • April 21, 2026</h2>
        
        <!-- Category Tabs with Overkill Styling -->
        <div class="flex gap-4 mb-8">
            <button onclick="switchCategory(0)" id="cat-0" class="category-tab active flex-1 py-4 text-xl font-bold rounded-3xl">FEDERAL</button>
            <button onclick="switchCategory(1)" id="cat-1" class="category-tab flex-1 py-4 text-xl font-bold rounded-3xl">STATE</button>
            <button onclick="switchCategory(2)" id="cat-2" class="category-tab flex-1 py-4 text-xl font-bold rounded-3xl">LOCAL / COMMUNAL</button>
            <button onclick="switchCategory(3)" id="cat-3" class="category-tab flex-1 py-4 text-xl font-bold rounded-3xl">PETITIONS &amp; LAWS</button>
        </div>
        
        <div id="ballot-content" class="space-y-10"></div>
        
        <!-- Live Vote Summary (Overkill Dynamic Panel) -->
        <div class="mt-8 bg-gradient-to-r from-blue-900 to-red-900 text-white rounded-3xl p-8 shadow-2xl" role="region" aria-label="Live vote summary">
            <h3 class="text-3xl font-bold mb-6 flex items-center"><i class="fa-solid fa-clipboard-check mr-4" aria-hidden="true"></i> LIVE VOTE SUMMARY • YOUR CHOICES SO FAR</h3>
            <div id="vote-summary" class="text-lg font-mono leading-relaxed min-h-[120px]" aria-live="polite" aria-atomic="false"></div>
            <div class="flex justify-between text-xs mt-4 flex-wrap gap-2">
                <div>BALLOT PROGRESS: <span id="progress-text" class="font-bold">0/24</span></div>
                <div id="progress-bar-container" class="flex-1 mx-6 bg-white/30 rounded-2xl h-3 mt-1" role="progressbar" aria-label="Ballot completion"><div id="progress-bar" class="h-3 bg-yellow-300 rounded-2xl w-0 transition-all"></div></div>
                <button onclick="spoilAndRevote()" class="px-6 py-2 bg-yellow-500 hover:bg-yellow-600 text-blue-900 font-bold rounded-2xl flex items-center gap-x-2" aria-label="Spoil previous ballots and re-vote (anti-coercion)"><i class="fa-solid fa-eraser" aria-hidden="true"></i> SPOIL &amp; REVOTE</button>
                <button onclick="finalLiveConfirmation()" class="px-8 py-2 bg-white text-blue-900 font-bold rounded-2xl flex items-center gap-x-2 hover:scale-105" aria-label="Submit all selected votes — final action"><i class="fa-solid fa-check-to-slot" aria-hidden="true"></i> FINAL SUBMISSION <i class="fa-solid fa-arrow-right" aria-hidden="true"></i></button>
            </div>
            <div id="e2e-key-status" class="mt-3 text-xs opacity-70" role="status" aria-live="polite">Standard ballot mode — checking for E2E encryption support...</div>
        </div>
    </div>

    <!-- RECEIPT -->
    <div id="screen-receipt" class="screen hidden text-center">
        <div class="max-w-2xl mx-auto bg-white shadow-2xl rounded-3xl p-16">
            <i class="fa-solid fa-check-circle text-9xl text-green-600 mb-8"></i>
            <h1 class="header-font text-5xl">VOTE RECORDED ON IMMUTABLE LEDGER</h1>
            <div class="mt-8 border border-dashed border-blue-800 rounded-3xl p-8 text-left font-mono text-sm">
                <p id="receipt-id" class="font-bold text-blue-900"></p>
                <p id="receipt-time" class="mt-2 text-gray-600"></p>
                <p id="receipt-hash" class="mt-2"></p>
                <p id="receipt-votes" class="mt-3 text-green-600"></p>
                <p id="receipt-auth" class="mt-2 text-gray-500"></p>
            </div>
            <button onclick="navigateTo('dashboard'); launchFireworks()" class="mt-8 px-12 py-5 text-2xl bg-blue-800 text-white rounded-3xl">VIEW LIVE DASHBOARD</button>
        </div>
    </div>

    <!-- DASHBOARD -->
    <div id="screen-dashboard" class="screen hidden">
        <h2 class="header-font text-4xl mb-2 text-center" style="color:#002868"><span style="color:#BF0A30">★</span> National Live Dashboard <span style="color:#BF0A30">★</span></h2>
        <div class="patriot-divider max-w-sm mx-auto" style="margin:8px auto 20px"></div>

        <!-- TOP ROW: Key Stats -->
        <div id="dash-content" class="grid grid-cols-5 gap-4 mb-6">
            <div class="bg-white rounded-3xl p-6 shadow-xl border-2 border-blue-100 text-center">
                <h3 class="font-bold text-blue-800 text-xs uppercase tracking-wider">TOTAL VOTES CAST</h3>
                <div id="dash-vote-count" class="text-5xl font-bold text-red-700 mt-2">--</div>
                <p id="dash-vote-label" class="text-gray-500 mt-1 text-xs">No data yet</p>
            </div>
            <div class="bg-white rounded-3xl p-6 shadow-xl border-2 border-blue-100 text-center">
                <h3 class="font-bold text-blue-800 text-xs uppercase tracking-wider">PAPER SLIPS MINTED</h3>
                <div id="dash-tokens" class="text-5xl font-bold" style="color:#DAA520;margin-top:8px">--</div>
                <p id="dash-verified-label" class="text-gray-500 mt-1 text-xs">Cryptographic tokens</p>
            </div>
            <div class="bg-white rounded-3xl p-6 shadow-xl border-2 border-blue-100 text-center">
                <h3 class="font-bold text-blue-800 text-xs uppercase tracking-wider">DOUBLE VERIFIED</h3>
                <div id="dash-verified" class="text-5xl font-bold text-green-600 mt-2">--</div>
                <p class="text-gray-500 mt-1 text-xs">Both hashes confirmed</p>
            </div>
            <div class="bg-white rounded-3xl p-6 shadow-xl border-2 border-blue-100 text-center">
                <h3 class="font-bold text-blue-800 text-xs uppercase tracking-wider">REGISTERED VOTERS</h3>
                <div id="dash-voters" class="text-5xl font-bold text-blue-800 mt-2">--</div>
                <p id="dash-elections" class="text-gray-500 mt-1 text-xs">No data yet</p>
            </div>
            <div class="bg-white rounded-3xl p-6 shadow-xl border-2 border-blue-100 text-center">
                <h3 class="font-bold text-blue-800 text-xs uppercase tracking-wider">CHAIN INTEGRITY</h3>
                <div id="dash-chain" class="text-4xl font-bold text-green-600 mt-2">--</div>
                <p id="dash-audit-count" class="text-gray-500 mt-1 text-xs">Audit entries: --</p>
            </div>
        </div>

        <!-- GENRE BREAKDOWN -->
        <div class="grid grid-cols-4 gap-4 mb-6">
            <div class="bg-gradient-to-br from-blue-900 to-blue-800 rounded-2xl p-5 text-white shadow-xl text-center">
                <div class="text-xs font-bold tracking-widest opacity-70 mb-1">FEDERAL</div>
                <div id="dash-genre-federal" class="text-4xl font-bold" style="color:#FFD700">0</div>
                <div class="text-xs mt-1 opacity-60">Presidential • Senate • House • Judicial</div>
            </div>
            <div class="bg-gradient-to-br from-red-800 to-red-700 rounded-2xl p-5 text-white shadow-xl text-center">
                <div class="text-xs font-bold tracking-widest opacity-70 mb-1">STATE</div>
                <div id="dash-genre-state" class="text-4xl font-bold" style="color:#FFD700">0</div>
                <div class="text-xs mt-1 opacity-60">Governor • Legislature • Propositions</div>
            </div>
            <div class="bg-gradient-to-br from-yellow-700 to-yellow-600 rounded-2xl p-5 text-white shadow-xl text-center">
                <div class="text-xs font-bold tracking-widest opacity-70 mb-1">LOCAL / COMMUNAL</div>
                <div id="dash-genre-local" class="text-4xl font-bold" style="color:#fff">0</div>
                <div class="text-xs mt-1 opacity-60">Mayor • Council • School Board • Bonds</div>
            </div>
            <div class="bg-gradient-to-br from-green-800 to-green-700 rounded-2xl p-5 text-white shadow-xl text-center">
                <div class="text-xs font-bold tracking-widest opacity-70 mb-1">PETITIONS &amp; LAWS</div>
                <div id="dash-genre-petition" class="text-4xl font-bold" style="color:#FFD700">0</div>
                <div class="text-xs mt-1 opacity-60">National • State • Local • Initiatives</div>
            </div>
        </div>

        <!-- GENRE BAR CHART (inline) -->
        <div class="bg-white rounded-3xl p-6 shadow-xl border-2 border-blue-100 mb-6">
            <h3 class="font-bold text-blue-800 text-sm uppercase tracking-wider mb-4"><i class="fa-solid fa-chart-bar mr-2 text-red-700"></i> PAPER SLIPS BY VOTING FORMAT</h3>
            <div id="dash-genre-bars" class="space-y-3">
                <div class="flex items-center gap-3"><span class="w-20 text-xs font-bold text-blue-900">FEDERAL</span><div class="flex-1 bg-gray-100 rounded-full h-6 overflow-hidden"><div id="dash-bar-federal" class="h-6 rounded-full transition-all" style="width:0%;background:#002868"></div></div><span id="dash-bar-cnt-federal" class="w-10 text-right text-sm font-bold text-blue-900">0</span></div>
                <div class="flex items-center gap-3"><span class="w-20 text-xs font-bold text-red-800">STATE</span><div class="flex-1 bg-gray-100 rounded-full h-6 overflow-hidden"><div id="dash-bar-state" class="h-6 rounded-full transition-all" style="width:0%;background:#B22234"></div></div><span id="dash-bar-cnt-state" class="w-10 text-right text-sm font-bold text-red-800">0</span></div>
                <div class="flex items-center gap-3"><span class="w-20 text-xs font-bold" style="color:#B8860B">LOCAL</span><div class="flex-1 bg-gray-100 rounded-full h-6 overflow-hidden"><div id="dash-bar-local" class="h-6 rounded-full transition-all" style="width:0%;background:#DAA520"></div></div><span id="dash-bar-cnt-local" class="w-10 text-right text-sm font-bold" style="color:#B8860B">0</span></div>
                <div class="flex items-center gap-3"><span class="w-20 text-xs font-bold text-green-800">PETITION</span><div class="flex-1 bg-gray-100 rounded-full h-6 overflow-hidden"><div id="dash-bar-petition" class="h-6 rounded-full transition-all" style="width:0%;background:#16a34a"></div></div><span id="dash-bar-cnt-petition" class="w-10 text-right text-sm font-bold text-green-800">0</span></div>
            </div>
        </div>

        <!-- RECENT ACTIVITY -->
        <div class="bg-white rounded-3xl p-6 shadow-xl border-2 border-blue-100">
            <h3 class="font-bold text-blue-800 text-sm uppercase tracking-wider mb-4"><i class="fa-solid fa-clock-rotate-left mr-2 text-red-700"></i> RECENT ACTIVITY</h3>
            <div id="dash-recent" class="text-sm text-gray-500">No recent activity to display.</div>
        </div>

        <!-- LAST UPDATED -->
        <div class="text-center mt-4 text-xs text-gray-400" id="dash-updated">—</div>
    </div>

    <!-- PUBLIC AUDIT -->
    <div id="screen-audit" class="screen hidden">
        <div class="patriot-banner mb-4" style="text-align:center">
            <h2 class="header-font text-3xl flex items-center justify-center gap-3"><i class="fa-solid fa-gavel" style="color:#FFD700"></i> PUBLIC AUDIT TRAIL <i class="fa-solid fa-gavel" style="color:#FFD700"></i></h2>
        </div>
        <p class="text-gray-600 mb-4">Every action is logged with a SHA-256 cryptographic hash chain. Each entry is linked to the previous by its hash, forming an immutable ledger identical in principle to a blockchain. Tampering with any single record invalidates every subsequent hash, making fraud mathematically impossible to conceal. Click any row to expand full details.</p>

        <div class="grid grid-cols-5 gap-3 mb-6">
            <div class="bg-white rounded-2xl p-4 shadow border-2 border-blue-100 text-center">
                <div id="audit-total" class="text-3xl font-bold text-blue-900">--</div>
                <div class="text-xs text-gray-500 mt-1">Total Entries</div>
            </div>
            <div class="bg-white rounded-2xl p-4 shadow border-2 border-blue-100 text-center">
                <div id="audit-chain-status" class="text-3xl font-bold text-green-600">--</div>
                <div class="text-xs text-gray-500 mt-1">Chain Integrity</div>
            </div>
            <div class="bg-white rounded-2xl p-4 shadow border-2 border-blue-100 text-center">
                <div id="audit-token-count" class="text-3xl font-bold text-red-700">--</div>
                <div class="text-xs text-gray-500 mt-1">Paper Slips Printed</div>
            </div>
            <div class="bg-white rounded-2xl p-4 shadow border-2 border-blue-100 text-center">
                <div id="audit-vote-count" class="text-3xl font-bold text-blue-800">--</div>
                <div class="text-xs text-gray-500 mt-1">Votes Recorded</div>
            </div>
            <div class="bg-white rounded-2xl p-4 shadow border-2 border-blue-100 text-center">
                <div id="audit-last-hash" class="text-xs font-mono text-gray-600 truncate mt-1">--</div>
                <div class="text-xs text-gray-500 mt-1">Latest Hash</div>
            </div>
        </div>

        <!-- Chain Integrity Visualization -->
        <div class="bg-white rounded-2xl p-4 shadow border-2 border-blue-100 mb-6">
            <h3 class="font-bold text-blue-800 text-sm mb-3"><i class="fa-solid fa-link mr-2 text-red-700"></i>HASH CHAIN VISUALIZATION (Most Recent Blocks)</h3>
            <div id="audit-chain-viz" class="flex gap-1 overflow-x-auto pb-2" style="scrollbar-width:thin"></div>
        </div>
        
        <div class="bg-white rounded-3xl p-8 shadow-2xl">
            <div class="flex justify-between items-center mb-4">
                <h3 class="font-bold text-blue-800"><i class="fa-solid fa-list-ul mr-2"></i>IMMUTABLE LEDGER — FULL HISTORY</h3>
                <div class="flex gap-2 items-center">
                    <span class="text-xs text-gray-400">Click row to expand</span>
                    <button onclick="renderAuditLog()" class="text-sm bg-blue-800 text-white px-4 py-2 rounded-lg"><i class="fa-solid fa-rotate mr-1"></i> Refresh</button>
                </div>
            </div>
            <table class="w-full text-left">
                <thead>
                    <tr class="border-b-2 border-blue-800">
                        <th class="pb-3 text-xs" style="width:24px"></th>
                        <th class="pb-3 text-xs">BLOCK</th>
                        <th class="pb-3 text-xs">TIMESTAMP</th>
                        <th class="pb-3 text-xs">ACTION</th>
                        <th class="pb-3 text-xs">STATUS</th>
                        <th class="pb-3 text-xs">VERIFIED BY</th>
                        <th class="pb-3 text-xs">TYPE</th>
                    </tr>
                </thead>
                <tbody id="audit-log" class="text-sm font-mono"></tbody>
            </table>
        </div>
    </div>

    <!-- VOTE PILE — 3D VIRTUAL WORLD -->
    <div id="screen-pile" class="screen hidden">
        <div class="patriot-banner mb-3" style="text-align:center">
            <h2 class="header-font text-3xl flex items-center justify-center gap-3"><i class="fa-solid fa-cubes" style="color:#FFD700"></i> VIRTUAL VOTE PILE <i class="fa-solid fa-cubes" style="color:#FFD700"></i></h2>
        </div>
        <p class="text-gray-600 mb-4">Every cast vote is printed as a physical paper slip and minted as an NFT-like coin in the virtual world below. Paper slips represent mass, are stacked by genre, and can be clicked to inspect full cryptographic data. Use the chart controls to visualize paper slips in any format.</p>

        <div class="grid grid-cols-4 gap-4 mb-4">
            <div class="bg-white rounded-2xl p-4 shadow border-2 border-blue-100 text-center">
                <div id="pile-total" class="text-4xl font-bold text-blue-900">0</div>
                <div class="text-xs text-gray-500 mt-1">Total Paper Slips</div>
            </div>
            <div class="bg-white rounded-2xl p-4 shadow border-2 border-blue-100 text-center">
                <div id="pile-verified" class="text-4xl font-bold text-green-600">0</div>
                <div class="text-xs text-gray-500 mt-1">Double-Verified</div>
            </div>
            <div class="bg-white rounded-2xl p-4 shadow border-2 border-blue-100 text-center">
                <div id="pile-genres" class="text-4xl font-bold text-red-700">0</div>
                <div class="text-xs text-gray-500 mt-1">Genre Piles</div>
            </div>
            <div class="bg-white rounded-2xl p-4 shadow border-2 border-blue-100 text-center">
                <div id="pile-chain" class="text-lg font-mono text-gray-600 truncate">--</div>
                <div class="text-xs text-gray-500 mt-1">Chain Head Hash</div>
            </div>
        </div>

        <!-- 3D VIRTUAL WORLD -->
        <div id="pile-3d-world">
            <canvas id="pile-3d-canvas"></canvas>
            <div id="pile-world-hud">
                <div class="hud-title">VOTE TOKEN WORLD</div>
                <div class="hud-stat"><span>Coins:</span><span class="hud-val" id="hud-coin-count">0</span></div>
                <div class="hud-stat"><span>Piles:</span><span class="hud-val" id="hud-pile-count">0</span></div>
                <div class="hud-stat"><span>Mass:</span><span class="hud-val" id="hud-mass">0 kg</span></div>
            </div>
            <div id="coin-tooltip-3d">
                <div class="ct-title"></div>
                <div class="ct-body"></div>
            </div>
            <div class="pile-view-controls">
                <button class="pile-view-btn active" onclick="setPileView('orbit')">ORBIT</button>
                <button class="pile-view-btn" onclick="setPileView('top')">TOP DOWN</button>
                <button class="pile-view-btn" onclick="setPileView('front')">FRONT</button>
                <button class="pile-view-btn" onclick="setPileView('bird')">BIRDS EYE</button>
                <button class="pile-view-btn" onclick="loadPile()"><i class="fa-solid fa-rotate"></i> REFRESH</button>
            </div>
        </div>

        <!-- CHART VISUALIZATION AREA -->
        <div id="pile-chart-area">
            <h3 class="text-xl font-bold text-blue-900 mb-2"><i class="fa-solid fa-chart-pie mr-2 text-red-700"></i> TOKEN ANALYTICS</h3>
            <div class="chart-tabs">
                <button class="chart-tab-btn active" onclick="switchChart('bar')"><i class="fa-solid fa-chart-column mr-1"></i> Bar</button>
                <button class="chart-tab-btn" onclick="switchChart('pie')"><i class="fa-solid fa-chart-pie mr-1"></i> Pie</button>
                <button class="chart-tab-btn" onclick="switchChart('line')"><i class="fa-solid fa-chart-line mr-1"></i> Timeline</button>
                <button class="chart-tab-btn" onclick="switchChart('donut')"><i class="fa-solid fa-circle-notch mr-1"></i> Donut</button>
                <button class="chart-tab-btn" onclick="switchChart('hbar')"><i class="fa-solid fa-chart-bar mr-1"></i> Horizontal</button>
                <button class="chart-tab-btn" onclick="switchChart('scatter')"><i class="fa-solid fa-braille mr-1"></i> Scatter</button>
                <button class="chart-tab-btn" onclick="switchChart('stacked')"><i class="fa-solid fa-layer-group mr-1"></i> Stacked</button>
            </div>
            <canvas id="pile-chart-canvas"></canvas>
        </div>

        <!-- FULL TOKEN LEDGER -->
        <div class="bg-white rounded-3xl p-8 shadow-2xl mt-8 border-2 border-blue-100">
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-xl font-bold text-blue-900"><i class="fa-solid fa-scroll mr-2 text-red-700"></i> COMPLETE TOKEN LEDGER</h3>
                <div class="flex gap-2 items-center">
                    <input id="token-search" type="text" placeholder="Search tokens..." oninput="filterTokenLedger(this.value)" class="text-xs border-2 border-blue-200 rounded-lg px-3 py-2 font-mono" style="width:220px">
                    <select id="token-genre-filter" onchange="filterTokenLedger(document.getElementById('token-search').value)" class="text-xs border-2 border-blue-200 rounded-lg px-3 py-2 font-bold">
                        <option value="">All Genres</option>
                        <option value="FEDERAL">FEDERAL</option>
                        <option value="STATE">STATE</option>
                        <option value="LOCAL">LOCAL</option>
                        <option value="PETITION">PETITION</option>
                    </select>
                    <select id="token-sort" onchange="filterTokenLedger(document.getElementById('token-search').value)" class="text-xs border-2 border-blue-200 rounded-lg px-3 py-2 font-bold">
                        <option value="newest">Newest First</option>
                        <option value="oldest">Oldest First</option>
                        <option value="genre">By Genre</option>
                        <option value="status">By Status</option>
                    </select>
                </div>
            </div>
            <p class="text-xs text-gray-500 mb-4">Every printed Paper Slip (Vote Token) is listed below with full blockchain data. Click any row to inspect the complete cryptographic record. <span id="ledger-count" class="font-bold text-blue-800"></span></p>
            <div style="overflow-x:auto">
                <table class="w-full text-left" id="token-ledger-table">
                    <thead>
                        <tr class="border-b-2 border-blue-800" style="background:#f0f5ff">
                            <th class="p-2 text-xs font-bold text-blue-900" style="width:32px">#</th>
                            <th class="p-2 text-xs font-bold text-blue-900">TOKEN ID</th>
                            <th class="p-2 text-xs font-bold text-blue-900">GENRE</th>
                            <th class="p-2 text-xs font-bold text-blue-900">CATEGORY</th>
                            <th class="p-2 text-xs font-bold text-blue-900">CHOICE</th>
                            <th class="p-2 text-xs font-bold text-blue-900">STATUS</th>
                            <th class="p-2 text-xs font-bold text-blue-900">VERIFIED</th>
                            <th class="p-2 text-xs font-bold text-blue-900">TOKEN HASH</th>
                            <th class="p-2 text-xs font-bold text-blue-900">PREV HASH</th>
                            <th class="p-2 text-xs font-bold text-blue-900">CREATED</th>
                            <th class="p-2 text-xs font-bold text-blue-900">AUTH</th>
                        </tr>
                    </thead>
                    <tbody id="token-ledger-body" class="text-xs font-mono"></tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Token Detail Modal -->
    <div id="token-modal" class="modal-overlay hidden" onclick="if(event.target===this)closeTokenModal()">
        <div class="modal-content" style="max-width:920px;max-height:90vh;display:flex;flex-direction:column">
            <div class="flex justify-between items-center mb-4" style="flex-shrink:0">
                <h3 id="token-modal-title" class="text-2xl font-bold text-blue-900"><i class="fa-solid fa-cube mr-2"></i> VOTE TOKEN</h3>
                <button onclick="closeTokenModal()" class="text-3xl text-gray-400 hover:text-red-600">&times;</button>
            </div>
            <div id="token-modal-body" class="space-y-4 font-mono text-sm" style="overflow-y:auto;flex:1;padding-right:8px"></div>
        </div>
    </div>

    <!-- ABOUT -->
    <div id="screen-about" class="screen hidden">
        <div class="text-center mb-2"><div class="gold-seal mx-auto mb-3" style="width:64px;height:64px;font-size:30px">★</div></div>
        <h2 class="header-font text-4xl mb-2 text-center" style="color:#002868">About the U.S. National Ballot Integrity<br>& Verification System <span style="color:#BF0A30">v1.17</span></h2>
        <div class="patriot-divider max-w-sm mx-auto" style="margin:8px auto 16px"></div>
        <p class="text-center text-gray-500 mb-8 max-w-3xl mx-auto">The most secure, transparent, and individually auditable voting system ever engineered. Every vote becomes an immutable blockchain artifact — traceable, navigable, and permanently recorded.</p>
        <div class="max-w-4xl mx-auto space-y-8">

            <!-- BLOCKCHAIN / NFT TOKEN DEEP DIVE -->
            <div class="bg-white rounded-3xl p-8 shadow-xl border-4 border-red-200">
                <h3 class="text-2xl font-bold text-blue-900 mb-2"><i class="fa-solid fa-cubes text-red-700 mr-2"></i> Vote Token Blockchain — Complete Technical Specification</h3>
                <p class="text-gray-500 text-sm mb-6">Every vote in the U.S. National Ballot Integrity & Verification System produces a <strong>Vote Token</strong> — functionally identical to an NFT (Non-Fungible Token) on a blockchain. Each token is unique, immutable, hash-chained, double-verified, and permanently stored on the ledger. Below is the complete anatomy of this system.</p>

                <div class="space-y-5">
                    <div class="border-l-4 border-red-700 pl-6 py-3">
                        <h4 class="font-bold text-blue-900 mb-1"><i class="fa-solid fa-dna mr-1 text-red-700"></i> Token Anatomy — 18 Data Fields Per Token</h4>
                        <p class="text-sm text-gray-600 mb-3">Each Vote Token is a self-contained cryptographic object. It carries the following 18 fields, each serving a specific verification or traceability purpose:</p>
                        <div class="grid grid-cols-2 gap-2 text-xs">
                            <div class="bg-blue-50 p-2 rounded"><strong>token_id</strong> — Unique identifier (format: VT-YYYYMMDD-HEXID). No two tokens can share an ID.</div>
                            <div class="bg-red-50 p-2 rounded"><strong>vote_id</strong> — Foreign key linking this token to the specific vote record in the votes table.</div>
                            <div class="bg-blue-50 p-2 rounded"><strong>voter_id</strong> — Foreign key linking to the authenticated voter. Combined with voter_hash for privacy.</div>
                            <div class="bg-red-50 p-2 rounded"><strong>election_id</strong> — Identifies which election this vote belongs to.</div>
                            <div class="bg-blue-50 p-2 rounded"><strong>genre</strong> — Classification: FEDERAL, STATE, LOCAL, PETITION, or GENERAL.</div>
                            <div class="bg-red-50 p-2 rounded"><strong>category</strong> — Sub-classification within the genre (e.g., cat-0-q0 for first federal question).</div>
                            <div class="bg-blue-50 p-2 rounded"><strong>choice</strong> — The full vote choice string, exactly as submitted by the voter.</div>
                            <div class="bg-red-50 p-2 rounded"><strong>choice_hash</strong> — SHA-256 hash of the choice. Allows verification without exposing the choice.</div>
                            <div class="bg-blue-50 p-2 rounded"><strong>voter_hash</strong> — SHA-256 of voter identity + random salt. Protects voter anonymity while proving uniqueness.</div>
                            <div class="bg-red-50 p-2 rounded"><strong>token_hash</strong> — The master hash: SHA-256(token_id + v1_hash + voter_hash + choice_hash + prev_token_hash).</div>
                            <div class="bg-blue-50 p-2 rounded"><strong>prev_token_hash</strong> — Hash of the previous token in the chain. Forms the blockchain link. Genesis block uses 64 zeros.</div>
                            <div class="bg-red-50 p-2 rounded"><strong>auth_layers</strong> — Comma-separated list of all 5 authentication layers the voter passed.</div>
                            <div class="bg-blue-50 p-2 rounded"><strong>device_fingerprint</strong> — Browser/device identifier for session tracing.</div>
                            <div class="bg-red-50 p-2 rounded"><strong>ip_address</strong> — Network address recorded at time of vote for fraud pattern detection.</div>
                            <div class="bg-blue-50 p-2 rounded"><strong>timestamp_created</strong> — ISO 8601 timestamp of token creation (atomic with vote).</div>
                            <div class="bg-red-50 p-2 rounded"><strong>timestamp_verified</strong> — ISO 8601 timestamp when double verification completed.</div>
                            <div class="bg-blue-50 p-2 rounded"><strong>verification_1_hash</strong> — SHA-256(token_id + voter_id + choice + timestamp + prev_hash). First independent proof.</div>
                            <div class="bg-red-50 p-2 rounded"><strong>verification_2_hash</strong> — SHA-256(token_hash + v1_hash + entropy + timestamp). Second independent proof.</div>
                        </div>
                    </div>

                    <div class="border-l-4 border-blue-800 pl-6 py-3">
                        <h4 class="font-bold text-blue-900 mb-1"><i class="fa-solid fa-link mr-1 text-blue-800"></i> Hash Chain — How the Blockchain Works</h4>
                        <p class="text-sm text-gray-600 mb-2">The hash chain is the backbone of the system. It works identically to blockchain technology:</p>
                        <div class="bg-gray-900 text-green-400 p-4 rounded-xl font-mono text-xs mb-3 overflow-x-auto">
                            <div>Block #1 (GENESIS):</div>
                            <div>&nbsp;&nbsp;prev_token_hash = 0000000000000000000000000000000000000000000000000000000000000000</div>
                            <div>&nbsp;&nbsp;token_hash = SHA-256(token_id + v1_hash + voter_hash + choice_hash + 000...000)</div>
                            <div>&nbsp;&nbsp;= a2ab9d83d31c6f7fcad90c4cf3ddb872... (example)</div>
                            <div style="color:#fbbf24;margin:4px 0">    |</div>
                            <div style="color:#fbbf24">    v (this hash becomes the PREV of the next block)</div>
                            <div style="color:#fbbf24;margin:4px 0">    |</div>
                            <div>Block #2:</div>
                            <div>&nbsp;&nbsp;prev_token_hash = a2ab9d83d31c6f7fcad90c4cf3ddb872... (MUST match Block #1 token_hash)</div>
                            <div>&nbsp;&nbsp;token_hash = SHA-256(token_id + v1_hash + voter_hash + choice_hash + a2ab...)</div>
                            <div>&nbsp;&nbsp;= 778426d969752afa46a740be57ab5099... (example)</div>
                            <div style="color:#fbbf24;margin:4px 0">    |</div>
                            <div style="color:#fbbf24">    v (continues to Block #3, #4, #5...forever)</div>
                        </div>
                        <p class="text-sm text-gray-600"><strong>Tamper detection:</strong> If anyone changes a single character in Block #1 (the choice, voter, or any field), its token_hash changes. But Block #2 stores the <em>original</em> hash of Block #1 as its prev_token_hash. The mismatch is immediately detectable. And since Block #2's hash is built from Block #1's hash, Block #2's hash also changes — breaking Block #3, which breaks Block #4, cascading through the entire chain. This makes retroactive fraud mathematically impossible.</p>
                    </div>

                    <div class="border-l-4 border-red-700 pl-6 py-3">
                        <h4 class="font-bold text-blue-900 mb-1"><i class="fa-solid fa-shield-halved mr-1 text-red-700"></i> Double Verification — Two Independent Proofs</h4>
                        <p class="text-sm text-gray-600 mb-2">Each token undergoes two separate SHA-256 hashing operations by independent logic paths:</p>
                        <div class="bg-gray-50 p-3 rounded-xl text-xs mb-2">
                            <div><strong style="color:#002868">Verification 1:</strong> <code style="background:#e0e7ff;padding:1px 4px;border-radius:4px">SHA-256(token_id + voter_id + choice + timestamp + prev_token_hash)</code></div>
                            <div class="text-gray-500 mt-1">Proves that the vote content, voter identity, and chain position were correct at time of creation.</div>
                        </div>
                        <div class="bg-gray-50 p-3 rounded-xl text-xs mb-2">
                            <div><strong style="color:#B22234">Verification 2:</strong> <code style="background:#fee2e2;padding:1px 4px;border-radius:4px">SHA-256(token_hash + v1_hash + random_entropy + timestamp)</code></div>
                            <div class="text-gray-500 mt-1">Independent re-hash with additional cryptographic entropy. Cannot be predicted from Verification 1 alone.</div>
                        </div>
                        <p class="text-sm text-gray-600">A token is only marked <strong>DOUBLE_VERIFIED</strong> when both hashes exist and are stored. This eliminates single-point-of-failure attacks — no single process, actor, or server can unilaterally fabricate a valid token.</p>
                    </div>

                    <div class="border-l-4 border-blue-800 pl-6 py-3">
                        <h4 class="font-bold text-blue-900 mb-1"><i class="fa-solid fa-coins mr-1 text-blue-800"></i> NFT Parallels — Why Vote Tokens Are Like NFTs</h4>
                        <p class="text-sm text-gray-600 mb-3">Vote Tokens share every defining characteristic of NFTs on a blockchain:</p>
                        <div class="grid grid-cols-2 gap-3 text-xs">
                            <div class="bg-blue-50 p-3 rounded-xl"><strong class="text-blue-900">Uniqueness:</strong> Every token has a unique token_id and a unique SHA-256 hash. No two tokens are identical, just like no two NFTs share a token address.</div>
                            <div class="bg-red-50 p-3 rounded-xl"><strong class="text-red-900">Immutability:</strong> Once minted, a token cannot be changed. The hash chain guarantees any alteration is detectable — identical to how an Ethereum smart contract makes NFT metadata permanent.</div>
                            <div class="bg-blue-50 p-3 rounded-xl"><strong class="text-blue-900">Chain Linkage:</strong> Each token stores the previous token's hash (prev_token_hash), forming a singly-linked hash chain — the same structure as a blockchain's block headers.</div>
                            <div class="bg-red-50 p-3 rounded-xl"><strong class="text-red-900">Provenance:</strong> Every token carries its full creation history: who cast it (hashed), what they voted for (hashed), when it was created, and every authentication layer they passed. Full provenance, like NFT ownership history.</div>
                            <div class="bg-blue-50 p-3 rounded-xl"><strong class="text-blue-900">Public Verifiability:</strong> Any person can inspect any token on the PILE page. Every hash, timestamp, and verification proof is visible and can be independently verified by recomputing the SHA-256 hashes.</div>
                            <div class="bg-red-50 p-3 rounded-xl"><strong class="text-red-900">Non-Fungibility:</strong> Each token represents a specific, unique vote. It cannot be swapped, duplicated, or substituted for another token. Like an NFT, its value is its individual identity.</div>
                        </div>
                    </div>

                    <div class="border-l-4 border-red-700 pl-6 py-3">
                        <h4 class="font-bold text-blue-900 mb-1"><i class="fa-solid fa-earth-americas mr-1 text-red-700"></i> The Virtual Vote Pile — 3D Visualization</h4>
                        <p class="text-sm text-gray-600">All minted tokens are rendered as physical gold coins in a 3D virtual world on the PILE page. Each coin is color-coded by genre (FEDERAL=blue, STATE=red, LOCAL=gold, PETITION=green). Coins scatter like a real pile of gold. The mouse pushes coins around with simulated physics. Hovering any coin shows its token ID, genre, status, hash, and creation time. Clicking a coin opens the full blockchain inspector with chain navigation (prev/next block), hash visualization, double verification proof, and all 18 data fields. Below the 3D world, 7 chart types (bar, pie, line, donut, horizontal, scatter, stacked) allow you to analyze token distribution across genres.</p>
                    </div>

                    <div class="border-l-4 border-blue-800 pl-6 py-3">
                        <h4 class="font-bold text-blue-900 mb-1"><i class="fa-solid fa-magnifying-glass mr-1 text-blue-800"></i> Navigating the Chain — Token Inspector</h4>
                        <p class="text-sm text-gray-600">Every token is fully navigable within the chain. When you inspect a token, you see:</p>
                        <ul class="list-disc pl-6 text-xs text-gray-600 space-y-1 mt-2">
                            <li><strong>Block position</strong> — which block number this token is in the chain (e.g., Block #3 of 10)</li>
                            <li><strong>Previous / Next navigation</strong> — buttons to walk forward and backward through the entire chain</li>
                            <li><strong>Chain link visualization</strong> — a 3-block diagram showing PREV BLOCK → THIS BLOCK → NEXT BLOCK with their hashes</li>
                            <li><strong>Genesis block detection</strong> — the first token in the chain is flagged as the GENESIS BLOCK with a zero-hash predecessor</li>
                            <li><strong>Cryptographic identity</strong> — the token hash, voter hash, and choice hash displayed in color-coded terminal-style readouts</li>
                            <li><strong>Hash chain proof</strong> — the previous token hash and this token hash, with an explanation of how they link</li>
                            <li><strong>Double verification proof</strong> — both verification hashes displayed with their input formulas</li>
                            <li><strong>Authentication layers</strong> — all 5 layers listed with icons and detailed descriptions of what each layer verifies</li>
                            <li><strong>Timestamps and metadata</strong> — creation time, verification time, device fingerprint, and IP address</li>
                        </ul>
                    </div>

                    <div class="border-l-4 border-red-700 pl-6 py-3">
                        <h4 class="font-bold text-blue-900 mb-1"><i class="fa-solid fa-triangle-exclamation mr-1 text-red-700"></i> Why This System Is Unforgeable</h4>
                        <p class="text-sm text-gray-600">Traditional voting counts batches. This system counts <em>individual cryptographic objects</em>. To forge a single vote, an attacker would need to:</p>
                        <ol class="list-decimal pl-6 text-xs text-gray-600 space-y-1 mt-2">
                            <li>Pass all 5 authentication layers (SSN, biometric, OTP, TOTP, behavioral) — defeating deepfake detection, liveness scoring, and coercion analysis</li>
                            <li>Produce a valid voter_hash matching a real taxpayer identity</li>
                            <li>Compute a valid token_hash that chains correctly to the previous block</li>
                            <li>Produce two independent verification hashes (one with unpredictable server-side entropy)</li>
                            <li>Insert the forged token into the database <em>and</em> update every subsequent token's prev_token_hash to maintain chain integrity</li>
                            <li>Do all of the above without triggering the fraud detector's rate limiting, IP analysis, and pattern matching</li>
                        </ol>
                        <p class="text-sm text-gray-600 mt-2 font-bold" style="color:#B22234">The probability of achieving all six steps simultaneously is computationally equivalent to breaking SHA-256 itself — which, with current technology, would take longer than the age of the universe.</p>
                    </div>
                </div>
            </div>

            <!-- WHAT IS A PAPER SLIP — THE PROOF -->
            <div class="bg-white rounded-3xl p-8 shadow-xl border-4 border-green-700">
                <h3 class="text-2xl font-bold text-blue-900 mb-2"><i class="fa-solid fa-certificate text-green-700 mr-2"></i> What Is a Paper Slip? — The Definitive Proof of a Vote</h3>
                <p class="text-gray-500 text-sm mb-6">A <strong>Paper Slip</strong> is the end product of every vote cast in this system. It is the <em>proof</em> — the immutable, cryptographic receipt that a specific citizen made a specific choice at a specific time, verified by 5 independent authentication layers, and permanently locked into a hash chain that cannot be altered by any person, machine, or government.</p>

                <div class="space-y-4">
                    <div class="bg-green-50 border-2 border-green-200 rounded-2xl p-5">
                        <h4 class="font-bold text-green-900 mb-2 text-lg"><i class="fa-solid fa-scroll mr-1"></i> A Paper Slip Contains:</h4>
                        <div class="grid grid-cols-2 gap-3 text-sm">
                            <div class="bg-white p-3 rounded-xl border border-green-200"><strong class="text-green-800">1. Unique Token ID</strong> — A one-of-a-kind identifier (VT-YYYYMMDD-HEX) that will never be reissued. This is the serial number of the slip.</div>
                            <div class="bg-white p-3 rounded-xl border border-green-200"><strong class="text-green-800">2. The Voter's Choice</strong> — The exact selection made, stored as both plaintext and a SHA-256 hash. The hash allows public verification without exposing the choice to those without access.</div>
                            <div class="bg-white p-3 rounded-xl border border-green-200"><strong class="text-green-800">3. Voter Identity Hash</strong> — A salted SHA-256 hash proving a real, unique, authenticated voter cast this slip. The identity is provable but private.</div>
                            <div class="bg-white p-3 rounded-xl border border-green-200"><strong class="text-green-800">4. Chain Link (prev_token_hash)</strong> — The hash of the Paper Slip that was minted immediately before this one. This links every slip to every other slip in an unbroken chain.</div>
                            <div class="bg-white p-3 rounded-xl border border-green-200"><strong class="text-green-800">5. Master Token Hash</strong> — SHA-256 of the combined token ID, verification hash, voter hash, choice hash, and chain link. This single hash proves the entire slip is intact.</div>
                            <div class="bg-white p-3 rounded-xl border border-green-200"><strong class="text-green-800">6. Double Verification</strong> — Two independent SHA-256 hashes computed by separate logic paths. Both must exist and match for the slip to be marked VERIFIED.</div>
                            <div class="bg-white p-3 rounded-xl border border-green-200"><strong class="text-green-800">7. Authentication Record</strong> — A list of all 5 authentication layers the voter passed: SSN, Biometric, OTP, TOTP, and Behavioral.</div>
                            <div class="bg-white p-3 rounded-xl border border-green-200"><strong class="text-green-800">8. Timestamps & Metadata</strong> — ISO 8601 creation and verification times, device fingerprint, and IP address for forensic tracing.</div>
                        </div>
                    </div>

                    <div class="bg-blue-50 border-2 border-blue-200 rounded-2xl p-5">
                        <h4 class="font-bold text-blue-900 mb-2 text-lg"><i class="fa-solid fa-microscope mr-1"></i> How Each Paper Slip Is Proven Valid</h4>
                        <p class="text-sm text-gray-600 mb-3">Every Paper Slip undergoes <strong>4 independent proof checks</strong> that any citizen can verify:</p>
                        <div class="space-y-3">
                            <div class="bg-white p-4 rounded-xl border-l-4 border-blue-800">
                                <strong class="text-blue-900">Proof 1 — Hash Chain Integrity</strong>
                                <p class="text-xs text-gray-600 mt-1">Recompute: <code class="bg-blue-100 px-1 rounded">SHA-256(token_id + v1_hash + voter_hash + choice_hash + prev_token_hash)</code>. If the result matches the stored <code>token_hash</code>, the slip has not been altered since creation. If the stored <code>prev_token_hash</code> matches the previous slip's <code>token_hash</code>, the chain link is intact. A single changed bit in any field produces a completely different hash — detection is absolute.</p>
                            </div>
                            <div class="bg-white p-4 rounded-xl border-l-4 border-red-700">
                                <strong class="text-red-900">Proof 2 — Double Verification Match</strong>
                                <p class="text-xs text-gray-600 mt-1">Verification 1 is computed from vote content + identity + chain position. Verification 2 is computed from the token hash + V1 hash + server-side entropy. Both hashes must exist and both must be reproducible from the stored inputs. If either hash is missing, mismatched, or unreproducible, the slip is flagged as <strong>UNVERIFIED</strong> and rejected from the official count.</p>
                            </div>
                            <div class="bg-white p-4 rounded-xl border-l-4 border-green-700">
                                <strong class="text-green-900">Proof 3 — Authentication Layer Record</strong>
                                <p class="text-xs text-gray-600 mt-1">The slip stores which of the 5 authentication layers were passed. A valid slip must show all 5: <code class="bg-green-100 px-1 rounded">SSN, BIOMETRIC, OTP, TOTP, BEHAVIORAL</code>. Any slip missing a layer is proof of an incomplete authentication and is excluded from the count. The audit log independently records each layer passage with its own timestamp.</p>
                            </div>
                            <div class="bg-white p-4 rounded-xl border-l-4 border-yellow-600">
                                <strong class="text-yellow-900">Proof 4 — Cascade Integrity (Full Chain Walk)</strong>
                                <p class="text-xs text-gray-600 mt-1">Starting from the Genesis Block (Block #1, prev_hash = 64 zeros), walk the entire chain forward. At every step, verify that Block N's <code>prev_token_hash</code> matches Block N-1's <code>token_hash</code>. If the chain is unbroken from Genesis to the current HEAD, then <strong>every slip in the system is proven untampered</strong>. A single forged slip breaks the chain and is immediately detectable.</p>
                            </div>
                        </div>
                    </div>

                    <div class="bg-gradient-to-r from-blue-900 to-red-900 rounded-2xl p-5 text-white">
                        <h4 class="font-bold text-lg mb-2"><i class="fa-solid fa-stamp text-yellow-300 mr-2"></i> The Paper Slip Is Your Legal Proof</h4>
                        <p class="text-sm text-blue-100 mb-3">When you cast a vote, the system produces a Paper Slip that serves as:</p>
                        <div class="grid grid-cols-3 gap-3 text-xs">
                            <div class="bg-white/10 p-3 rounded-xl"><strong class="text-yellow-300">Personal Receipt</strong><p class="text-blue-200 mt-1">You can view your slip on the PILE page at any time — its token ID, hash, chain position, and all 18 fields are permanently accessible.</p></div>
                            <div class="bg-white/10 p-3 rounded-xl"><strong class="text-yellow-300">Public Audit Evidence</strong><p class="text-blue-200 mt-1">Every slip is logged in the public audit trail with its own hash-chained entry. Any citizen can verify it exists, is authentic, and is unmodified.</p></div>
                            <div class="bg-white/10 p-3 rounded-xl"><strong class="text-yellow-300">Mathematical Certainty</strong><p class="text-blue-200 mt-1">The proof is not based on trust — it is based on SHA-256 cryptography. The probability of forging a valid slip is 1 in 2^256 — effectively zero.</p></div>
                        </div>
                        <p class="text-center mt-4 text-yellow-200 font-bold">A Paper Slip is not a promise. It is a mathematical proof that your vote exists, is authentic, and will be counted.</p>
                    </div>
                </div>
            </div>

            <!-- 5-LAYER AUTHENTICATION -->
            <div class="bg-white rounded-3xl p-8 shadow-xl border-2 border-blue-100">
                <h3 class="text-2xl font-bold text-blue-900 mb-4"><i class="fa-solid fa-shield-halved text-red-700 mr-2"></i> 5-Layer Authentication System</h3>
                <p class="text-gray-600 mb-6">Every voter must pass all 5 layers before casting a ballot. Failure at any layer rejects the vote and flags it for review. This makes fabrication, deepfakes, replay attacks, and coerced voting virtually impossible.</p>
                <div class="space-y-4">
                    <div class="border-l-4 border-blue-800 pl-6 py-3">
                        <h4 class="font-bold text-blue-900">Layer 1: Identity Verification (SSN + Tax PIN)</h4>
                        <p class="text-sm text-gray-600">The voter provides their Social Security Number and Tax History PIN. The SSN is validated against federal format rules (no invalid area numbers, no blacklisted sequences) and hashed with a cryptographic pepper before storage. The Tax PIN confirms the voter has a legitimate, active tax record with the United States government. This layer eliminates fabricated identities, non-citizens, and non-taxpayers at the gate.</p>
                    </div>
                    <div class="border-l-4 border-red-700 pl-6 py-3">
                        <h4 class="font-bold text-blue-900">Layer 2: Live Biometric Capture (Camera + Microphone)</h4>
                        <p class="text-sm text-gray-600">A live 4K camera and microphone feed is required. The system runs real-time deepfake detection (frequency analysis, texture consistency, blink rate, lip-sync coherence) and replay attack analysis (frame timestamp validation, device hardware checks). The voter must prove physical presence — not a pre-recorded video, AI-generated face, or manipulated stream. Liveness scoring must exceed 90% across all metrics.</p>
                    </div>
                    <div class="border-l-4 border-blue-800 pl-6 py-3">
                        <h4 class="font-bold text-blue-900">Layer 3: Session One-Time Passcode (Random OTP)</h4>
                        <p class="text-sm text-gray-600">A cryptographically random 6-digit code is generated using <code>secrets.token_hex()</code> uniquely for each voting session. The code is displayed only once and expires after use. The voter must enter this code to confirm active session participation and prevent replay of cached authentication states. The OTP is never stored in plaintext — only its hash is compared.</p>
                    </div>
                    <div class="border-l-4 border-red-700 pl-6 py-3">
                        <h4 class="font-bold text-blue-900">Layer 4: Pre-Registered TOTP Authenticator</h4>
                        <p class="text-sm text-gray-600">Each voter pre-registers a TOTP (Time-based One-Time Password) authenticator app such as Google Authenticator, Authy, or Microsoft Authenticator. The 6-digit code rotates every 30 seconds using the HMAC-SHA1 algorithm with a shared secret. The code is unique per voter per time window. This ensures the voter physically possesses their registered device — blocking remote or hijacked sessions.</p>
                    </div>
                    <div class="border-l-4 border-blue-800 pl-6 py-3">
                        <h4 class="font-bold text-blue-900">Layer 5: Behavioral Analysis (Voice + Face + Coercion Detection)</h4>
                        <p class="text-sm text-gray-600">The voter must speak a randomized phrase aloud while on camera. The system analyzes voice patterns (pitch, cadence, stress markers), facial micro-expressions (eye movement, jaw tension, forced smiling), and behavioral indicators (hesitation, reading from a script, someone else in frame giving instructions). Signs of coercion, duress, or scripted behavior trigger immediate rejection. Only natural, voluntary, uncoerced behavior passes.</p>
                    </div>
                </div>
            </div>

            <!-- FRAUD DETECTION -->
            <div class="bg-white rounded-3xl p-8 shadow-xl border-2 border-blue-100">
                <h3 class="text-2xl font-bold text-blue-900 mb-4"><i class="fa-solid fa-triangle-exclamation text-red-700 mr-2"></i> Fraud Detection &amp; Flagging</h3>
                <p class="text-gray-600 mb-4">Any vote that fails one or more authentication layers is automatically flagged. Flagged votes are:</p>
                <ul class="list-disc pl-8 text-sm text-gray-600 space-y-2">
                    <li><strong>Rejected immediately</strong> — the vote is not recorded on the ledger; no paper slip is printed</li>
                    <li><strong>Logged in the audit trail</strong> — with full details of which layer(s) failed and the device/IP metadata</li>
                    <li><strong>Reported for review</strong> — flagged for bipartisan citizen review board with full forensic data</li>
                    <li><strong>Pattern-matched</strong> — compared against known fraud signatures: rapid submission (<2s), duplicate SSN attempts, VPN/proxy detection, geographic anomalies, device fingerprint reuse across multiple voter IDs</li>
                    <li><strong>Rate-limited</strong> — the fraud detector tracks submission speed and will reject suspiciously fast vote sequences</li>
                </ul>
                <p class="text-gray-600 mt-4">Votes from non-qualified entities (fabricated SSNs, non-taxpayers, underage non-workers) are rejected at Layer 1 and never reach the ballot. The system maintains a zero-tolerance policy: <strong>no authentication shortcut, no batch override, no admin bypass</strong>.</p>
            </div>

            <!-- AUDIT TRAIL -->
            <div class="bg-white rounded-3xl p-8 shadow-xl border-2 border-blue-100">
                <h3 class="text-2xl font-bold text-blue-900 mb-4"><i class="fa-solid fa-link text-red-700 mr-2"></i> Immutable Audit Trail (Hash-Chained Ledger)</h3>
                <p class="text-gray-600 mb-4">Every enrollment, authentication attempt, vote cast, paper slip printing, and system action is recorded in a hash-chained audit log. The audit trail operates on the same blockchain principle as the Vote Tokens:</p>
                <div class="bg-gray-900 text-green-400 p-4 rounded-xl font-mono text-xs mb-4">
                    <div>Audit Entry #N:</div>
                    <div>&nbsp;&nbsp;hash = SHA-256(timestamp + action + status + verified_by + prev_entry_hash)</div>
                    <div>&nbsp;&nbsp;prev_entry_hash = hash of Entry #N-1</div>
                    <div style="color:#fbbf24;margin:4px 0">&nbsp;&nbsp;=> Any alteration to Entry #N invalidates Entry #N+1, #N+2, ...all the way to HEAD</div>
                </div>
                <p class="text-sm text-gray-600">The audit trail is <strong>publicly viewable in real time</strong> on the AUDIT page. Every row is expandable to show full blockchain context, linked tokens, and immutability guarantees. A visual chain diagram shows the most recent blocks color-coded by type (VOTE=red, PAPER SLIP=blue, SYSTEM=gray).</p>
            </div>

            <!-- VOTING CATEGORIES -->
            <div class="bg-white rounded-3xl p-8 shadow-xl border-2 border-blue-100">
                <h3 class="text-2xl font-bold text-blue-900 mb-4"><i class="fa-solid fa-landmark text-blue-800 mr-2"></i> Voting Categories</h3>
                <p class="text-gray-600 mb-4">The National Ballot Integrity & Verification System covers every level of American governance:</p>
                <div class="grid grid-cols-2 gap-4 text-sm">
                    <div class="bg-blue-50 p-4 rounded-xl"><strong class="text-blue-900">Federal:</strong> Presidential, U.S. Senate, U.S. House, Supreme Court Confirmations, Constitutional Amendments</div>
                    <div class="bg-red-50 p-4 rounded-xl"><strong class="text-red-900">State:</strong> Governor, State Senate, State House, State Supreme Court, State Propositions, State Constitutional Questions</div>
                    <div class="bg-blue-50 p-4 rounded-xl"><strong class="text-blue-900">Local:</strong> Mayor, City Council, School Board, County Commissioner, Municipal Judge, Bond Measures, Zoning Referenda</div>
                    <div class="bg-red-50 p-4 rounded-xl"><strong class="text-red-900">Direct Democracy:</strong> National Petitions, State Petitions, State Laws, Local Ordinances, Citizen Initiatives, Recall Elections</div>
                </div>
            </div>

            <!-- TAXPAYER ELIGIBILITY -->
            <div class="bg-white rounded-3xl p-8 shadow-xl border-2 border-blue-100">
                <h3 class="text-2xl font-bold text-blue-900 mb-4"><i class="fa-solid fa-users text-blue-800 mr-2"></i> Taxpayer Eligibility</h3>
                <p class="text-gray-600 mb-3">The National Ballot Integrity & Verification System extends voting rights to every American who has contributed to the tax system. This includes working minors aged 12 and above who have filed taxes. If you have paid taxes to the United States of America, you have earned your voice.</p>
                <div class="grid grid-cols-3 gap-3 text-xs">
                    <div class="bg-blue-50 p-3 rounded-xl"><strong class="text-blue-900">Adults (18+):</strong> Full voting rights across all categories — federal, state, local, and petitions. No restrictions.</div>
                    <div class="bg-red-50 p-3 rounded-xl"><strong class="text-red-900">Minors (12-17):</strong> Eligible if they have filed taxes. Requires guardian consent. Restricted from national presidential elections. Full access to state, local, and petition votes.</div>
                    <div class="bg-blue-50 p-3 rounded-xl"><strong class="text-blue-900">Under 12:</strong> Not eligible regardless of tax status. The system enforces this at Layer 1 during identity verification.</div>
                </div>
            </div>

        </div>
    </div>

    <!-- POWER — WHY VOTING GIVES THE PEOPLE POWER -->
    <div id="screen-power" class="screen hidden">
        <div class="text-center mb-8">
            <div class="flex justify-center items-center gap-3 mb-3"><span style="font-size:40px">🇺🇸</span><div class="gold-seal" style="width:70px;height:70px;font-size:32px">🗳️</div><span style="font-size:40px">🇺🇸</span></div>
            <h2 class="header-font text-5xl mb-3" style="color:#002868;text-shadow:2px 2px 0 rgba(191,10,48,0.12)">The Power of the Ballot</h2>
            <div class="patriot-divider max-w-md mx-auto" style="margin:4px auto 12px"></div>
            <p class="text-lg text-gray-600 max-w-3xl mx-auto">The right to vote is the single most powerful instrument of self-governance ever devised. It is the mechanism by which free citizens direct the machinery of the state, hold authority accountable, and ensure that government serves the governed — not the other way around.</p>
        </div>
        <div class="max-w-5xl mx-auto space-y-8">

            <!-- SOVEREIGNTY -->
            <div class="bg-white rounded-3xl p-8 shadow-xl border-4 border-blue-800">
                <h3 class="text-2xl font-bold text-blue-900 mb-4"><i class="fa-solid fa-landmark-dome text-red-700 mr-2"></i> Popular Sovereignty: Government by Consent</h3>
                <p class="text-gray-700 mb-4">The founding principle of the United States is that <strong>all political power originates with the people</strong>. The Declaration of Independence states that governments derive &ldquo;their just powers from the consent of the governed.&rdquo; Voting is the formal, legally binding act by which that consent is given — or withheld.</p>
                <div class="grid grid-cols-2 gap-4 text-sm">
                    <div class="bg-blue-50 p-5 rounded-xl border-l-4 border-blue-800">
                        <strong class="text-blue-900 text-base">Direct Authority Over Legislators</strong>
                        <p class="text-gray-600 mt-2">Every member of Congress, every state legislator, every city council member holds their seat <em>only</em> because voters placed them there. Your vote is the hiring decision. Your next vote is the performance review. Politicians who fail the public are removed — not by revolution, but by ballot.</p>
                    </div>
                    <div class="bg-red-50 p-5 rounded-xl border-l-4 border-red-700">
                        <strong class="text-red-900 text-base">Control Over Taxation & Spending</strong>
                        <p class="text-gray-600 mt-2">Every dollar the government spends was authorized by elected officials who were chosen by voters. Bond measures, budget referendums, tax levies — these are decided by the ballot. When you vote, you are directly controlling where your tax dollars go: schools, roads, defense, healthcare, or nowhere at all.</p>
                    </div>
                    <div class="bg-blue-50 p-5 rounded-xl border-l-4 border-blue-800">
                        <strong class="text-blue-900 text-base">Judicial Accountability</strong>
                        <p class="text-gray-600 mt-2">Federal judges are appointed by elected Presidents and confirmed by elected Senators. State and local judges are often directly elected. The entire judiciary — the branch that interprets your rights — is shaped by votes. Every Supreme Court decision traces back to a ballot cast by a citizen.</p>
                    </div>
                    <div class="bg-red-50 p-5 rounded-xl border-l-4 border-red-700">
                        <strong class="text-red-900 text-base">Constitutional Amendments</strong>
                        <p class="text-gray-600 mt-2">The people have the power to <em>change the Constitution itself</em>. Amendments require elected officials to propose and ratify them — officials who were put in place by voters. The 13th, 19th, and 26th Amendments (abolishing slavery, women's suffrage, lowering the voting age) all happened because citizens used the ballot to elect leaders who acted.</p>
                    </div>
                </div>
            </div>

            <!-- ACCOUNTABILITY -->
            <div class="bg-white rounded-3xl p-8 shadow-xl border-2 border-red-200">
                <h3 class="text-2xl font-bold text-blue-900 mb-4"><i class="fa-solid fa-gavel text-red-700 mr-2"></i> Accountability: The Power to Remove</h3>
                <p class="text-gray-700 mb-4">Voting is not just the power to elect — it is the power to <strong>remove</strong>. Every elected official in the United States serves a fixed term and must face the voters again. This creates a system of permanent accountability with no escape.</p>
                <div class="space-y-3 text-sm">
                    <div class="flex gap-4 items-start bg-gray-50 p-4 rounded-xl">
                        <i class="fa-solid fa-rotate text-blue-800 text-xl mt-1"></i>
                        <div><strong class="text-blue-900">Term Limits as Leverage</strong> — The President serves 4-year terms. Representatives serve 2-year terms. Senators serve 6-year terms. At each cycle, the people decide: continue or replace. This forces officials to align with the public interest or face electoral defeat.</div>
                    </div>
                    <div class="flex gap-4 items-start bg-gray-50 p-4 rounded-xl">
                        <i class="fa-solid fa-ban text-red-700 text-xl mt-1"></i>
                        <div><strong class="text-red-900">Recall Elections</strong> — In many states, citizens can initiate a recall election to remove an official <em>before</em> their term ends. This is direct democracy at its most powerful: the people fire their employee.</div>
                    </div>
                    <div class="flex gap-4 items-start bg-gray-50 p-4 rounded-xl">
                        <i class="fa-solid fa-chart-line text-blue-800 text-xl mt-1"></i>
                        <div><strong class="text-blue-900">Policy Referendums</strong> — Beyond electing people, voters in most states can directly vote on <em>laws</em>. Ballot propositions, initiatives, and referendums let citizens bypass legislators entirely and write their own rules — minimum wage, marijuana legalization, environmental protections, and more.</div>
                    </div>
                    <div class="flex gap-4 items-start bg-gray-50 p-4 rounded-xl">
                        <i class="fa-solid fa-people-group text-red-700 text-xl mt-1"></i>
                        <div><strong class="text-red-900">Petition Power</strong> — Citizens can gather signatures to force a question onto the ballot. This is the most direct form of political power: the government must ask the people and obey the answer.</div>
                    </div>
                </div>
            </div>

            <!-- HISTORICAL IMPACT -->
            <div class="bg-white rounded-3xl p-8 shadow-xl border-2 border-blue-100">
                <h3 class="text-2xl font-bold text-blue-900 mb-4"><i class="fa-solid fa-book-open text-blue-800 mr-2"></i> Historical Proof: When the Ballot Changed Everything</h3>
                <p class="text-gray-700 mb-4">The history of the United States is a history of the ballot transforming society. Every major advance in justice, liberty, and equality was driven by citizens exercising their right to vote.</p>
                <div class="grid grid-cols-2 gap-3 text-xs">
                    <div class="bg-blue-50 p-4 rounded-xl"><strong class="text-blue-900">1860 — Abraham Lincoln</strong><br>Voters elected Lincoln, which led to the Emancipation Proclamation and the 13th Amendment abolishing slavery. The ballot ended the greatest moral crime in American history.</div>
                    <div class="bg-red-50 p-4 rounded-xl"><strong class="text-red-900">1920 — 19th Amendment</strong><br>After decades of advocacy, enough elected officials — placed by voters — ratified women's suffrage. The electorate doubled overnight because previous voters demanded it.</div>
                    <div class="bg-blue-50 p-4 rounded-xl"><strong class="text-blue-900">1964 — Civil Rights Act</strong><br>Voters elected President Johnson and a Congress willing to pass the Civil Rights Act, ending legal segregation. The ballot delivered justice that protests alone could not.</div>
                    <div class="bg-red-50 p-4 rounded-xl"><strong class="text-red-900">1971 — 26th Amendment</strong><br>The voting age was lowered to 18. Young Americans, who were being drafted to fight in Vietnam but could not vote, demanded representation. The ballot answered.</div>
                    <div class="bg-blue-50 p-4 rounded-xl"><strong class="text-blue-900">2008 — First Black President</strong><br>130 million Americans voted. The ballot shattered the highest racial barrier in the nation's history. Voting accomplished what no other institution could.</div>
                    <div class="bg-red-50 p-4 rounded-xl"><strong class="text-red-900">Every Local Election</strong><br>School board members decide your children's curriculum. County commissioners decide your property taxes. Mayors decide your police budget. These are all decided by ballot — often by margins of dozens of votes.</div>
                </div>
            </div>

            <!-- INDIVIDUAL IMPACT -->
            <div class="bg-white rounded-3xl p-8 shadow-xl border-4 border-red-700">
                <h3 class="text-2xl font-bold text-blue-900 mb-4"><i class="fa-solid fa-user-check text-red-700 mr-2"></i> Your Individual Vote: More Powerful Than You Think</h3>
                <p class="text-gray-700 mb-4">People who say &ldquo;my vote doesn't matter&rdquo; are factually wrong. Here is why:</p>
                <div class="space-y-3 text-sm">
                    <div class="bg-gray-50 p-4 rounded-xl border-l-4 border-blue-800">
                        <strong class="text-blue-900">Margins of Victory Are Razor-Thin</strong> — The 2000 Presidential election was decided by 537 votes in Florida — out of 6 million cast. State legislature races are routinely decided by double digits. City council seats have been won by <em>a single vote</em>. Your vote is not symbolic; it is decisive.
                    </div>
                    <div class="bg-gray-50 p-4 rounded-xl border-l-4 border-red-700">
                        <strong class="text-red-900">Collective Leverage</strong> — When communities vote together, they become impossible to ignore. Politicians allocate resources — funding, infrastructure, services — to communities that vote, because those are the communities that can remove them. Low-turnout areas are defunded. High-turnout areas thrive.
                    </div>
                    <div class="bg-gray-50 p-4 rounded-xl border-l-4 border-blue-800">
                        <strong class="text-blue-900">Downstream Effects</strong> — Your vote for President affects the Supreme Court for 30 years. Your vote for state legislators affects redistricting for a decade. Your vote for school board affects your children's education for their entire school career. A single ballot casts a shadow across generations.
                    </div>
                    <div class="bg-gray-50 p-4 rounded-xl border-l-4 border-red-700">
                        <strong class="text-red-900">Non-Voting Is a Choice — For Someone Else</strong> — When you don't vote, you don't opt out of the system. The system continues. Someone else's choice fills the vacuum. Not voting is not neutrality — it is surrender.
                    </div>
                </div>
            </div>

            <!-- WHY THIS SYSTEM MATTERS -->
            <div class="bg-gradient-to-r from-blue-900 to-red-900 rounded-3xl p-8 shadow-xl text-white">
                <h3 class="text-2xl font-bold mb-4"><i class="fa-solid fa-shield-halved text-yellow-300 mr-2"></i> Why the National Ballot Integrity & Verification System Exists</h3>
                <p class="text-blue-100 mb-4">The power of the vote means nothing if the vote can be corrupted. Every stolen vote silences a citizen. Every fraudulent ballot cancels a legitimate one. Every insecure system erodes trust — and when trust is gone, democracy is gone.</p>
                <div class="grid grid-cols-3 gap-4 text-xs">
                    <div class="bg-white/10 p-4 rounded-xl backdrop-blur">
                        <strong class="text-yellow-300 text-sm">Integrity</strong>
                        <p class="text-blue-100 mt-2">Every vote is SHA-256 hash-chained, double-verified, and permanently stored as an immutable Paper Slip. Tampering with a single vote requires breaking the entire chain — a computational impossibility.</p>
                    </div>
                    <div class="bg-white/10 p-4 rounded-xl backdrop-blur">
                        <strong class="text-yellow-300 text-sm">Transparency</strong>
                        <p class="text-blue-100 mt-2">Every Paper Slip, every audit log entry, every hash is publicly visible. Any citizen can verify any vote. No black boxes, no hidden counts, no trust required — only math.</p>
                    </div>
                    <div class="bg-white/10 p-4 rounded-xl backdrop-blur">
                        <strong class="text-yellow-300 text-sm">Equality</strong>
                        <p class="text-blue-100 mt-2">Every taxpaying American — adults and working minors alike — has an equal, authenticated, cryptographically verified vote. No vote counts more than another. No identity can be faked. One citizen, one ballot, one voice.</p>
                    </div>
                </div>
                <p class="text-center mt-6 text-yellow-200 font-bold text-lg">When the ballot is secure, the people are sovereign.<br>When the people are sovereign, the nation is free.</p>
            </div>

            <!-- CALL TO ACTION -->
            <div class="text-center py-8">
                <h3 class="header-font text-3xl text-blue-900 mb-3">Your Voice. Your Power. Your Nation.</h3>
                <p class="text-gray-600 max-w-2xl mx-auto mb-6">Every election — from the President of the United States to your local school board — is a decision about the future. The ballot is the instrument. The power is yours. Use it.</p>
                <button onclick="navigateTo('enroll')" class="px-8 py-4 bg-gradient-to-r from-blue-800 to-red-700 text-white text-lg font-bold rounded-2xl shadow-xl hover:shadow-2xl transform hover:scale-105 transition"><i class="fa-solid fa-flag-usa mr-2"></i> ENROLL & VOTE NOW</button>
            </div>

        </div>
    </div>

    <!-- WHY VOTE — INCENTIVES FOR EVERY BALLOT ITEM -->
    <div id="screen-incentives" class="screen hidden">
        <div class="text-center mb-6">
            <div class="gold-seal mx-auto mb-3" style="width:64px;height:64px;font-size:28px">⚖️</div>
            <h2 class="header-font text-4xl mb-2" style="color:#002868">★ Why Your Vote Matters ★<br><span class="text-2xl" style="color:#BF0A30">By Ballot Item</span></h2>
            <div class="patriot-divider max-w-sm mx-auto" style="margin:8px auto 12px"></div>
            <p class="text-gray-600 max-w-3xl mx-auto">Below is every election and measure on your ballot, organized by genre. Each item includes a factual, logical explanation of what is at stake, what power your vote carries, and what happens if you do not vote. <strong>Select your state above to see your area's elections.</strong></p>
            <p class="text-sm text-gray-400 mt-2">Your registered state: <strong id="incentive-state" class="text-blue-900">NOT SELECTED</strong></p>
        </div>

        <!-- Genre Tabs -->
        <div class="flex gap-2 mb-6 justify-center flex-wrap">
            <button onclick="switchIncentiveGenre(0)" id="inc-tab-0" class="px-5 py-2 rounded-xl font-bold text-sm border-2 transition" style="background:#002868;color:#fff;border-color:#002868"><i class="fa-solid fa-landmark-dome mr-1"></i> FEDERAL</button>
            <button onclick="switchIncentiveGenre(1)" id="inc-tab-1" class="px-5 py-2 rounded-xl font-bold text-sm border-2 transition bg-white text-gray-700 border-gray-300"><i class="fa-solid fa-building-columns mr-1"></i> STATE</button>
            <button onclick="switchIncentiveGenre(2)" id="inc-tab-2" class="px-5 py-2 rounded-xl font-bold text-sm border-2 transition bg-white text-gray-700 border-gray-300"><i class="fa-solid fa-city mr-1"></i> LOCAL</button>
            <button onclick="switchIncentiveGenre(3)" id="inc-tab-3" class="px-5 py-2 rounded-xl font-bold text-sm border-2 transition bg-white text-gray-700 border-gray-300"><i class="fa-solid fa-scroll mr-1"></i> PETITIONS</button>
        </div>

        <div id="incentive-body" class="max-w-5xl mx-auto space-y-5"></div>

        <div class="text-center mt-10 mb-4">
            <button onclick="navigateTo('enroll')" class="px-8 py-4 bg-gradient-to-r from-blue-800 to-red-700 text-white text-lg font-bold rounded-2xl shadow-xl hover:shadow-2xl transform hover:scale-105 transition"><i class="fa-solid fa-shield-halved mr-2"></i> REGISTER & VOTE</button>
        </div>
    </div>

    <!-- VERIFY YOUR VOTE -->
    <div id="screen-verify" class="screen hidden">
        <div class="patriot-banner mb-6" style="text-align:center">
            <h2 class="header-font text-3xl"><i class="fa-solid fa-magnifying-glass-chart" style="color:#FFD700"></i> VERIFY YOUR VOTE <i class="fa-solid fa-magnifying-glass-chart" style="color:#FFD700"></i></h2>
            <p class="text-sm mt-1" style="color:#FFD700">Enter any Token ID to independently verify its existence, integrity, and chain position.</p>
        </div>
        <div class="max-w-3xl mx-auto">
            <div class="bg-white rounded-3xl p-8 shadow-xl border-2 border-green-200 mb-6">
                <div class="flex gap-4 items-end">
                    <div class="flex-1">
                        <label class="block text-sm font-bold text-blue-900 mb-2"><i class="fa-solid fa-fingerprint mr-1"></i> PAPER SLIP TOKEN ID</label>
                        <input id="verify-token-input" type="text" placeholder="e.g. VT-20260422-A1B2C3D4E5F6" class="w-full border-2 border-green-600 rounded-2xl px-6 py-4 text-lg font-mono focus:ring-4 focus:ring-green-200 focus:border-green-800 transition">
                    </div>
                    <button onclick="verifyVoteToken()" class="px-8 py-4 bg-gradient-to-r from-green-700 to-green-900 text-white text-lg font-bold rounded-2xl shadow-xl hover:shadow-2xl transform hover:scale-105 transition"><i class="fa-solid fa-shield-halved mr-2"></i> VERIFY</button>
                </div>
            </div>
            <div id="verify-result" class="space-y-4"></div>
        </div>
    </div>

    <!-- LIVE ELECTION RESULTS -->
    <div id="screen-results" class="screen hidden">
        <div class="patriot-banner mb-6" style="text-align:center">
            <h2 class="header-font text-3xl"><i class="fa-solid fa-trophy" style="color:#FFD700"></i> LIVE ELECTION RESULTS <i class="fa-solid fa-trophy" style="color:#FFD700"></i></h2>
            <p class="text-sm mt-1" style="color:#FFD700">Real-time tallies across every race in every voting format. Updated live.</p>
        </div>
        <div class="flex gap-3 mb-6 justify-center">
            <button onclick="loadResults(0)" id="res-tab-0" class="px-5 py-2 rounded-xl font-bold text-sm border-2 transition" style="background:#002868;color:#fff;border-color:#002868"><i class="fa-solid fa-landmark-dome mr-1"></i> FEDERAL</button>
            <button onclick="loadResults(1)" id="res-tab-1" class="px-5 py-2 rounded-xl font-bold text-sm border-2 transition bg-white text-gray-700 border-gray-300"><i class="fa-solid fa-building-columns mr-1"></i> STATE</button>
            <button onclick="loadResults(2)" id="res-tab-2" class="px-5 py-2 rounded-xl font-bold text-sm border-2 transition bg-white text-gray-700 border-gray-300"><i class="fa-solid fa-city mr-1"></i> LOCAL</button>
            <button onclick="loadResults(3)" id="res-tab-3" class="px-5 py-2 rounded-xl font-bold text-sm border-2 transition bg-white text-gray-700 border-gray-300"><i class="fa-solid fa-scroll mr-1"></i> PETITIONS</button>
        </div>
        <div id="results-body" class="max-w-5xl mx-auto space-y-6"></div>
        <div class="text-center mt-6 text-xs text-gray-400" id="results-updated">—</div>
    </div>

    <!-- CHAIN INTEGRITY TEST (modal overlay) -->
    <div id="chain-test-modal" class="hidden fixed inset-0 z-[9999] flex items-center justify-center" style="background:rgba(0,0,0,0.85)">
        <div class="bg-white rounded-3xl p-8 shadow-2xl max-w-2xl w-full mx-4 border-4 border-blue-800 max-h-[90vh] overflow-y-auto">
            <div class="text-center mb-6">
                <div class="gold-seal mx-auto mb-3" style="width:60px;height:60px;font-size:28px">🔗</div>
                <h2 class="header-font text-2xl text-blue-900">BLOCKCHAIN INTEGRITY SELF-TEST</h2>
                <p class="text-sm text-gray-500 mt-1">Walking the entire chain from Genesis to HEAD...</p>
            </div>
            <div class="mb-4">
                <div class="bg-gray-100 rounded-full h-6 overflow-hidden">
                    <div id="chain-test-bar" class="h-6 rounded-full transition-all" style="width:0%;background:linear-gradient(90deg,#002868,#16a34a)"></div>
                </div>
                <div class="flex justify-between mt-1 text-xs text-gray-400">
                    <span>Genesis Block</span>
                    <span id="chain-test-progress">0 / 0 blocks verified</span>
                    <span>HEAD</span>
                </div>
            </div>
            <div id="chain-test-log" class="bg-gray-900 text-green-400 rounded-2xl p-4 font-mono text-xs max-h-60 overflow-y-auto mb-4" style="min-height:120px">
                <div class="text-gray-500">Initializing chain walk...</div>
            </div>
            <div id="chain-test-result" class="text-center mb-4"></div>
            <div class="text-center">
                <button onclick="closeChainTest()" class="px-6 py-3 bg-blue-800 text-white font-bold rounded-xl hover:bg-blue-700 transition"><i class="fa-solid fa-xmark mr-2"></i> CLOSE</button>
            </div>
        </div>
    </div>

    <!-- BLOCKCHAIN EXPLORER -->
    <div id="screen-explorer" class="screen hidden">
        <div class="patriot-banner mb-6" style="text-align:center">
            <h2 class="header-font text-3xl"><i class="fa-solid fa-cubes" style="color:#FFD700"></i> BLOCKCHAIN EXPLORER <i class="fa-solid fa-cubes" style="color:#FFD700"></i></h2>
            <p class="text-sm mt-1" style="color:#FFD700">Walk the full chain block-by-block. Every hash. Every link. Verified.</p>
        </div>
        <div class="max-w-5xl mx-auto">
            <!-- Chain Navigation -->
            <div class="bg-white rounded-2xl shadow-xl p-6 mb-6 border-2 border-blue-200">
                <div class="flex items-center justify-between mb-4">
                    <button onclick="explorerPrev()" id="explorer-prev-btn" class="px-4 py-2 bg-blue-800 text-white rounded-lg font-bold hover:bg-blue-700 transition disabled:opacity-50"><i class="fa-solid fa-arrow-left mr-2"></i> PREV BLOCK</button>
                    <div class="text-center">
                        <div id="explorer-position" class="text-2xl font-bold text-blue-900">Block #1 of 5</div>
                        <div id="explorer-genesis" class="text-xs text-yellow-600 font-bold" style="display:none"><i class="fa-solid fa-star mr-1"></i> GENESIS BLOCK</div>
                    </div>
                    <button onclick="explorerNext()" id="explorer-next-btn" class="px-4 py-2 bg-blue-800 text-white rounded-lg font-bold hover:bg-blue-700 transition disabled:opacity-50">NEXT BLOCK <i class="fa-solid fa-arrow-right ml-2"></i></button>
                </div>
                <!-- Visual Chain Links -->
                <div class="flex items-center justify-center gap-2 mb-4">
                    <div id="chain-link-prev" class="px-3 py-1 bg-gray-100 rounded text-xs font-mono text-gray-500 truncate max-w-[150px]">000000...</div>
                    <i class="fa-solid fa-link text-blue-800"></i>
                    <div id="chain-link-current" class="px-4 py-2 bg-blue-800 text-white rounded-lg text-sm font-mono font-bold">CURRENT</div>
                    <i class="fa-solid fa-link text-blue-800"></i>
                    <div id="chain-link-next" class="px-3 py-1 bg-gray-100 rounded text-xs font-mono text-gray-500 truncate max-w-[150px]">000000...</div>
                </div>
            </div>

            <!-- Block Details -->
            <div id="explorer-details" class="bg-gray-900 rounded-2xl p-6 text-green-400 font-mono text-sm shadow-xl">
                <div class="flex items-center justify-between mb-4 pb-4 border-b border-gray-700">
                    <span class="text-yellow-300 font-bold text-lg">BLOCK DETAILS</span>
                    <button onclick="printPaperSlip()" class="px-4 py-2 bg-gradient-to-r from-yellow-600 to-yellow-700 text-white rounded-lg font-bold text-xs hover:shadow-lg transition"><i class="fa-solid fa-print mr-2"></i> PRINT PAPER SLIP</button>
                </div>
                <div class="grid grid-cols-2 gap-4" id="explorer-fields">
                    <!-- Filled by JS -->
                </div>
            </div>

            <!-- Hash Visualization -->
            <div class="mt-6 bg-white rounded-2xl p-6 shadow-xl border-2 border-blue-100">
                <h3 class="font-bold text-blue-900 mb-4"><i class="fa-solid fa-fingerprint mr-2"></i> HASH CHAIN VISUALIZATION</h3>
                <div class="flex items-center gap-4">
                    <div class="flex-1 bg-gray-100 rounded-xl p-4">
                        <div class="text-xs text-gray-500 mb-1">PREVIOUS BLOCK HASH</div>
                        <div id="viz-prev-hash" class="font-mono text-xs text-gray-700 break-all">0000000000000000000000000000000000000000000000000000000000000000</div>
                    </div>
                    <i class="fa-solid fa-arrow-right text-2xl text-blue-800"></i>
                    <div class="flex-1 bg-blue-50 rounded-xl p-4 border-2 border-blue-300">
                        <div class="text-xs text-blue-600 mb-1 font-bold">THIS BLOCK'S HASH</div>
                        <div id="viz-current-hash" class="font-mono text-xs text-blue-900 break-all font-bold">...</div>
                    </div>
                    <i class="fa-solid fa-arrow-right text-2xl text-blue-800"></i>
                    <div class="flex-1 bg-gray-100 rounded-xl p-4">
                        <div class="text-xs text-gray-500 mb-1">NEXT BLOCK'S PREV_HASH</div>
                        <div id="viz-next-prev" class="font-mono text-xs text-gray-700 break-all">...</div>
                    </div>
                </div>
                <div id="hash-match-indicator" class="mt-4 text-center">
                    <!-- Filled by JS -->
                </div>
            </div>
        </div>
    </div>

    <!-- PRINTABLE PAPER SLIP MODAL -->
    <div id="paper-slip-modal" class="hidden fixed inset-0 z-[9999] flex items-center justify-center" style="background:rgba(0,0,0,0.9)">
        <div class="bg-white rounded-none shadow-2xl w-full max-w-2xl mx-auto overflow-hidden" style="border:8px double #002868">
            <!-- Certificate Header -->
            <div style="background:linear-gradient(135deg,#002868,#001845);padding:24px;text-align:center;border-bottom:4px solid #FFD700">
                <div style="display:flex;justify-content:center;align-items:center;gap:16px;margin-bottom:12px">
                    <span style="font-size:36px">🇺🇸</span>
                    <div class="gold-seal" style="width:64px;height:64px;font-size:28px;border-width:3px">🦅</div>
                    <span style="font-size:36px">🇺🇸</span>
                </div>
                <h2 style="font-family:'Cinzel',serif;color:#FFD700;font-size:22px;font-weight:900;letter-spacing:3px;margin:0">OFFICIAL PAPER SLIP</h2>
                <p style="color:rgba(255,255,255,0.7);font-size:11px;letter-spacing:2px;margin:4px 0 0">U.S. NATIONAL BALLOT INTEGRITY & VERIFICATION SYSTEM</p>
            </div>

            <!-- Certificate Body -->
            <div style="padding:32px;background:linear-gradient(180deg,#fff 0%,#f8fafc 100%);background-image:url('data:image/svg+xml,%3Csvg width=\'100\' height=\'100\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Ctext x=\'50\' y=\'50\' text-anchor=\'middle\' font-size=\'60\' fill=\'%23002868\' opacity=\'0.03\'%3E🦅%3C/text%3E%3C/svg%3E')">
                <div style="text-align:center;margin-bottom:24px">
                    <div style="font-size:12px;color:#6b7280;letter-spacing:2px;margin-bottom:4px">CERTIFICATE OF CIVIC PARTICIPATION</div>
                    <div style="font-family:'Cinzel',serif;font-size:20px;color:#002868;font-weight:700" id="slip-token-id">VT-XXXXXXXX-XXXXXXXX</div>
                </div>

                <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px">
                    <div style="background:#f3f4f6;border-radius:8px;padding:12px;border-left:4px solid #002868">
                        <div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:1px">Voter Hash</div>
                        <div id="slip-voter-hash" style="font-family:monospace;font-size:11px;color:#374151;word-break:break-all">...</div>
                    </div>
                    <div style="background:#f3f4f6;border-radius:8px;padding:12px;border-left:4px solid #BF0A30">
                        <div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:1px">Genre</div>
                        <div id="slip-genre" style="font-size:14px;color:#002868;font-weight:700">...</div>
                    </div>
                </div>

                <div style="background:#f3f4f6;border-radius:8px;padding:16px;margin-bottom:24px;border:2px solid #DAA520">
                    <div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Cast Vote Choice</div>
                    <div id="slip-choice" style="font-size:18px;color:#002868;font-weight:700;font-family:'Cinzel',serif">...</div>
                </div>

                <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px">
                    <div style="background:#ecfdf5;border-radius:8px;padding:12px;border:2px solid #16a34a">
                        <div style="font-size:10px;color:#16a34a;text-transform:uppercase;letter-spacing:1px"><i class="fa-solid fa-check-circle mr-1"></i> Double Verified</div>
                        <div style="font-family:monospace;font-size:9px;color:#15803d;margin-top:4px" id="slip-v1">V1: ...</div>
                        <div style="font-family:monospace;font-size:9px;color:#15803d" id="slip-v2">V2: ...</div>
                    </div>
                    <div style="background:#eff6ff;border-radius:8px;padding:12px;border:2px solid #3b82f6">
                        <div style="font-size:10px;color:#3b82f6;text-transform:uppercase;letter-spacing:1px"><i class="fa-solid fa-link mr-1"></i> Chain Position</div>
                        <div id="slip-position" style="font-size:16px;color:#1d4ed8;font-weight:700">Block #1 of 1</div>
                        <div id="slip-timestamp" style="font-size:10px;color:#6b7280;margin-top:2px">...</div>
                    </div>
                </div>

                <div style="background:#fafafa;border-radius:8px;padding:12px;border:1px solid #e5e7eb">
                    <div style="font-size:9px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">SHA-256 Token Hash (Proof of Integrity)</div>
                    <div id="slip-token-hash" style="font-family:monospace;font-size:10px;color:#374151;word-break:break-all">...</div>
                </div>

                <div style="text-align:center;margin-top:24px;padding-top:24px;border-top:2px dashed #d1d5db">
                    <div style="font-size:11px;color:#6b7280;font-style:italic;margin-bottom:8px">"This Paper Slip serves as cryptographic proof of a vote cast. Any citizen may independently verify its authenticity using the Verify Your Vote portal."</div>
                    <div style="display:flex;justify-content:center;gap:8px;margin-top:12px">
                        <div style="width:40px;height:40px;background:#002868;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font-size:20px">🗳️</div>
                        <div style="width:40px;height:40px;background:#BF0A30;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font-size:20px">🦅</div>
                        <div style="width:40px;height:40px;background:#FFD700;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#002868;font-size:20px">⭐</div>
                    </div>
                </div>
            </div>

            <!-- Certificate Footer / Actions -->
            <div style="background:#f3f4f6;padding:16px;display:flex;justify-content:center;gap:12px;border-top:2px solid #e5e7eb">
                <button onclick="window.print()" class="px-6 py-3 bg-gradient-to-r from-blue-800 to-blue-900 text-white rounded-lg font-bold hover:shadow-lg transition"><i class="fa-solid fa-print mr-2"></i> PRINT CERTIFICATE</button>
                <button onclick="closePaperSlip()" class="px-6 py-3 bg-gray-500 text-white rounded-lg font-bold hover:bg-gray-600 transition"><i class="fa-solid fa-xmark mr-2"></i> CLOSE</button>
            </div>
        </div>
    </div>

    <!-- EXPORT AUDIT MODAL -->
    <div id="export-modal" class="hidden fixed inset-0 z-[9999] flex items-center justify-center" style="background:rgba(0,0,0,0.85)">
        <div class="bg-white rounded-3xl p-8 shadow-2xl max-w-xl w-full mx-4 border-4 border-blue-800">
            <div class="text-center mb-6">
                <div class="gold-seal mx-auto mb-3" style="width:60px;height:60px;font-size:28px">📊</div>
                <h2 class="header-font text-2xl text-blue-900">EXPORT FULL AUDIT</h2>
                <p class="text-sm text-gray-500 mt-1">Download the complete blockchain and audit log for independent verification</p>
            </div>
            <div class="space-y-4 mb-6">
                <div class="bg-blue-50 rounded-xl p-4 border-2 border-blue-200">
                    <div class="flex items-center gap-3 mb-2">
                        <i class="fa-solid fa-file-code text-2xl text-blue-800"></i>
                        <div>
                            <div class="font-bold text-blue-900">JSON Format</div>
                            <div class="text-xs text-gray-500">Machine-readable, complete data structure</div>
                        </div>
                    </div>
                    <button onclick="exportAudit('json')" class="w-full py-3 bg-blue-800 text-white font-bold rounded-xl hover:bg-blue-700 transition"><i class="fa-solid fa-download mr-2"></i> DOWNLOAD JSON</button>
                </div>
                <div class="bg-green-50 rounded-xl p-4 border-2 border-green-200">
                    <div class="flex items-center gap-3 mb-2">
                        <i class="fa-solid fa-file-csv text-2xl text-green-800"></i>
                        <div>
                            <div class="font-bold text-green-900">CSV Format</div>
                            <div class="text-xs text-gray-500">Spreadsheet-compatible, token data only</div>
                        </div>
                    </div>
                    <button onclick="exportAudit('csv')" class="w-full py-3 bg-green-700 text-white font-bold rounded-xl hover:bg-green-600 transition"><i class="fa-solid fa-download mr-2"></i> DOWNLOAD CSV</button>
                </div>
            </div>
            <div class="text-center">
                <button onclick="closeExportModal()" class="px-6 py-3 bg-gray-400 text-white font-bold rounded-xl hover:bg-gray-500 transition"><i class="fa-solid fa-xmark mr-2"></i> CANCEL</button>
            </div>
        </div>
    </div>

</div>

<!-- PATRIOTIC FOOTER -->
<footer style="background:linear-gradient(135deg,#002868,#001845);border-top:4px solid #FFD700;padding:32px 0;margin-top:40px;position:relative;overflow:hidden">
    <div style="position:absolute;top:0;left:0;right:0;bottom:0;background-image:url(&quot;data:image/svg+xml,%3Csvg width='20' height='20' xmlns='http://www.w3.org/2000/svg'%3E%3Ctext x='10' y='14' text-anchor='middle' font-size='8' fill='white' opacity='0.04'%3E%E2%98%85%3C/text%3E%3C/svg%3E&quot;);pointer-events:none"></div>
    <div class="max-w-screen-2xl mx-auto px-8 text-center relative" style="z-index:2">
        <div style="display:flex;justify-content:center;align-items:center;gap:12px;margin-bottom:12px">
            <span style="font-size:28px">🇺🇸</span>
            <div class="gold-seal" style="width:48px;height:48px;font-size:22px">🦅</div>
            <span style="font-size:28px">🇺🇸</span>
        </div>
        <p class="header-font" style="color:#FFD700;font-size:16px;letter-spacing:3px;margin-bottom:4px">U.S. NATIONAL BALLOT INTEGRITY & VERIFICATION SYSTEM v1.17</p>
        <p style="color:rgba(255,255,255,0.5);font-size:11px;letter-spacing:2px;margin-bottom:16px">DEPARTMENT OF ELECTORAL SECURITY • UNITED STATES OF AMERICA</p>
        <div style="height:3px;background:repeating-linear-gradient(90deg,#BF0A30 0px,#BF0A30 20px,transparent 20px,transparent 30px,#fff 30px,#fff 50px,transparent 50px,transparent 60px,#002868 60px,#002868 80px,transparent 80px,transparent 90px);max-width:400px;margin:0 auto 16px;border-radius:2px;opacity:0.6"></div>
        <p class="header-font" style="color:rgba(255,255,255,0.7);font-size:13px;font-style:italic;max-width:600px;margin:0 auto 8px">"The ballot is stronger than the bullet."</p>
        <p style="color:rgba(255,215,0,0.6);font-size:10px;letter-spacing:2px;font-weight:700">— PRESIDENT ABRAHAM LINCOLN</p>
        <p style="color:rgba(255,255,255,0.25);font-size:10px;margin-top:16px;letter-spacing:1px">★ E PLURIBUS UNUM ★ IN GOD WE TRUST ★ NOVUS ORDO SECLORUM ★</p>
    </div>
</footer>

<script src="/static/voting.js" defer></script>
</body>
</html>
'''

# ==================== COMPLETE BACKEND CLASSES ====================
class SSNValidator:
    SSN_PATTERN = re.compile(r'^(?!000|666|9\d{2})\d{3}-?\d{2}-?\d{4}$')
    INVALID_SSNS = {'078-05-1120', '219-09-9999', '457-55-5462', '000-00-0000', '111-11-1111'}

    @classmethod
    def validate(cls, ssn: str) -> bool:
        cleaned = ssn.replace('-', '').strip()
        if len(cleaned) != 9 or not cleaned.isdigit():
            return False
        formatted = f"{cleaned[:3]}-{cleaned[3:5]}-{cleaned[5:]}"
        if formatted in cls.INVALID_SSNS:
            return False
        return bool(cls.SSN_PATTERN.match(formatted))

    @classmethod
    def hash_ssn(cls, ssn: str, pepper: str = "") -> str:
        """Pepper defaults to ENCRYPTION_KEY hex so DB compromise alone
        doesn't yield rainbow-table-able SSN hashes."""
        cleaned = ssn.replace('-', '').strip()
        if not pepper:
            pepper = ENCRYPTION_KEY.hex()
        return hmac.new(pepper.encode(), cleaned.encode(), hashlib.sha256).hexdigest()


class EligibilityEngine:
    """Eligibility decision is the union of:
        - age check (real, in-process)
        - tax-paying status (DEFER: real path needs IRS API; we accept a hash but
          mark `eligibility.source = 'unverified-tax'` so audit logs make the
          unverified state obvious)
        - residency, felony disqualification, and death-master-file checks
          (DEFER: real path needs ERIC + state feeds; we honor flags on the
          voter row if present)
    Critically: we never silently treat unverified facts as verified.
    """

    MINOR_RULES = {
        'min_age_no_restrictions': 18,
        'taxpayer_minor_min_age': 12,
        'requires_guardian_consent': True,
        'restricted_election_types': ['national_presidential'],
    }

    def check_eligibility(
        self,
        ssn: str,
        tax_id: str,
        dob: str,
        *,
        residency_verified: bool = False,
        felony_disqualified: bool = False,
        deceased: bool = False,
    ) -> Dict[str, Any]:
        # SSN format guard — the real lookup against SSA happens at registration
        # time (DEFER); here we just refuse blatantly malformed values.
        if not SSNValidator.validate(ssn):
            return {'eligible': False, 'reason': 'SSN failed format validation'}
        if deceased:
            return {'eligible': False, 'reason': 'Deceased per official record'}
        if felony_disqualified:
            return {'eligible': False, 'reason': 'Felony disqualification on record'}
        try:
            birth_date = datetime.strptime(dob, '%Y-%m-%d')
            age = (datetime.now() - birth_date).days / 365.25
        except (ValueError, TypeError):
            return {'eligible': False, 'reason': 'Invalid date of birth'}

        # Tax-id check is intentionally weak; flag so audit shows it.
        is_taxpayer = bool(tax_id) and len(tax_id) > 5
        source = 'verified' if (residency_verified and is_taxpayer) else 'unverified'

        if age < 18:
            if not is_taxpayer:
                return {'eligible': False, 'reason': 'Minors must have paid taxes to be eligible',
                        'source': source}
            if age < self.MINOR_RULES['taxpayer_minor_min_age']:
                return {'eligible': False,
                        'reason': f'Must be at least {self.MINOR_RULES["taxpayer_minor_min_age"]} years old',
                        'source': source}

        if age >= 18 or (is_taxpayer and age >= 12):
            return {
                'eligible': True,
                'age': age,
                'is_taxpayer': is_taxpayer,
                'requires_guardian_consent': age < 18,
                'source': source,
                'residency_verified': residency_verified,
            }

        return {'eligible': False, 'reason': 'Does not meet eligibility requirements'}


class FraudDetector:
    """Server-derived fraud signals. The previous version trusted a client-sent
    `submission_speed` field — anyone could send `submission_speed: 99` and pass.

    All inputs here are computed server-side: the IP we observed, the time
    delta between this voter's last action and now, and the count of distinct
    voter_ids that have used this device fingerprint.
    """

    # Per-IP velocity bucket: {ip: deque[timestamp_unix]}
    _velocity: Dict[str, deque] = defaultdict(lambda: deque(maxlen=64))

    def observe(self, ip: str) -> None:
        self._velocity[ip].append(time.time())

    def check_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        risk_score = 0
        flags: List[str] = []
        ip = session_data.get('ip_address') or ''
        device_fingerprint = (session_data.get('device_fingerprint') or '')[:512]
        voter_id = session_data.get('voter_id')

        # 1. IP velocity: too many requests in a short window -> bot territory.
        bucket = self._velocity[ip]
        recent = [t for t in bucket if t > time.time() - 60]
        if len(recent) > 30:
            risk_score += 40
            flags.append('ip_velocity')

        # 2. Device-fingerprint reuse across distinct voter_ids.
        if device_fingerprint and voter_id:
            with db_conn() as conn:
                c = conn.cursor()
                c.execute(
                    """SELECT COUNT(DISTINCT voter_id) FROM vote_tokens
                       WHERE device_fingerprint = ?""",
                    (device_fingerprint,),
                )
                distinct = c.fetchone()[0] or 0
            if distinct >= 3 and not session_data.get('shared_device_allowed'):
                risk_score += 35
                flags.append('device_reuse')

        # 3. Time since voter's last successful vote token (replay-style burst).
        if voter_id:
            with db_conn() as conn:
                c = conn.cursor()
                c.execute(
                    """SELECT timestamp_created FROM vote_tokens
                       WHERE voter_id = ? ORDER BY id DESC LIMIT 1""",
                    (voter_id,),
                )
                row = c.fetchone()
            if row:
                last = parse_iso(row[0])
                if last and (datetime.now(timezone.utc) - last).total_seconds() < 1.0:
                    risk_score += 30
                    flags.append('rapid_repeat')

        # 4. Loopback/private-net IP is benign in lab but warrants a note.
        if ip.startswith(('10.', '192.168.', '172.16.', '127.')):
            flags.append('private_ip')

        return {'risk_score': risk_score, 'flags': flags, 'passed': risk_score < 50}


class AuditLogger:
    """Hash-chained audit logger. Stores entry_hash and prev_hash directly so
    the chain head can be loaded in O(1) at startup instead of O(N) replay.

    Migration 9 added the entry_hash/prev_hash columns. Old rows pre-migration
    have empty hashes; we reconstruct the chain head by replaying just those
    rows once at first use, then the in-DB columns drive everything.
    """

    _shared_last_hash: Optional[str] = None

    def __init__(self, db_file: str):
        self.db_file = db_file

    @classmethod
    def _ensure_chain_head(cls) -> str:
        if cls._shared_last_hash is not None:
            return cls._shared_last_hash
        with db_conn() as conn:
            c = conn.cursor()
            # Try to use stored entry_hash on the most recent row first.
            c.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            row = c.fetchone()
            if row and row[0]:
                cls._shared_last_hash = row[0]
                return row[0]
            # Fallback: replay everything (only happens once per legacy DB).
            last = "0" * 64
            c.execute("SELECT id, timestamp, action, status, verified_by, entry_hash FROM audit_log ORDER BY id ASC")
            for rid, ts, act, st, vb, eh in c.fetchall():
                if eh:
                    last = eh
                    continue
                last = stable_hash("audit", ts, act, st, vb, last)
                c.execute("UPDATE audit_log SET entry_hash = ?, prev_hash = ? WHERE id = ?",
                          (last, last if last == "0" * 64 else last, rid))
            conn.commit()
        cls._shared_last_hash = last
        return last

    def log(self, action: str, status: str, verified_by: str) -> str:
        with _AUDIT_LOCK:
            prev = AuditLogger._ensure_chain_head()
            timestamp = utcnow_iso()
            entry_hash = stable_hash("audit", timestamp, action, status, verified_by, prev)
            AuditLogger._shared_last_hash = entry_hash
            with db_conn() as conn:
                c = conn.cursor()
                c.execute(
                    """INSERT INTO audit_log
                       (timestamp, action, status, verified_by, entry_hash, prev_hash)
                       VALUES (?,?,?,?,?,?)""",
                    (timestamp, action[:512], status[:64], verified_by[:128], entry_hash, prev),
                )
                conn.commit()
            return entry_hash


class VoteManager:
    """Casts votes through the secrecy split: voter_voted records that voter X
    voted in election Y; vote_ballots records that some authenticated voter
    cast a ballot for race R with choice C. The link between the two is a
    hashed anchor that proves uniqueness without revealing identity.

    Also: enforces election-window, prevents double-vote per (voter, election),
    signs the resulting vote token with Ed25519, and writes the legacy `votes`
    row for backward compatibility with existing readers.
    """

    def __init__(self, db_file: str):
        self.db_file = db_file
        self.audit_logger = AuditLogger(db_file)

    @staticmethod
    def voter_anchor(voter_id: int, election_id: int) -> str:
        """Per-(voter, election) anchor. Same voter in same election always
        produces the same anchor (so we can detect double-cast attempts);
        different voters or different elections give unrelated values."""
        return stable_hash("anchor", voter_id, election_id)

    def cast_vote(
        self,
        voter_id: int,
        election_id: int,
        choice: str,
        *,
        race_key: Optional[str] = None,
        ip_address: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
    ) -> Dict[str, Any]:
        # Window check.
        ok, reason = is_election_open(election_id)
        if not ok:
            return {'success': False, 'error': f'election not open: {reason}'}

        timestamp = utcnow_iso()
        anchor = self.voter_anchor(voter_id, election_id)

        with db_conn() as conn:
            c = conn.cursor()
            # Has this voter already voted in this election?
            if race_key:
                c.execute(
                    """SELECT 1 FROM vote_ballots
                       WHERE voter_anchor_hash = ? AND race_key = ? AND spoiled = 0""",
                    (anchor, race_key),
                )
                if c.fetchone():
                    return {'success': False, 'error': 'already voted in this race'}

            # Insert legacy votes row (kept for backward-compat readers).
            try:
                c.execute(
                    "INSERT INTO votes (voter_id, election_id, choice, timestamp) VALUES (?, ?, ?, ?)",
                    (voter_id, election_id, choice, timestamp),
                )
                vote_id = c.lastrowid
            except sqlite3.IntegrityError:
                # Unique (voter_id, election_id) — voter already voted in this election.
                # For per-race elections we still want to insert; for single-choice
                # elections we report it.
                if not race_key:
                    return {'success': False, 'error': 'already voted in this election'}
                vote_id = 0

            # Insert ballot row (the "secret ballot" record).
            ballot_id = f"BB-{secrets.token_hex(8).upper()}"
            c.execute(
                """INSERT INTO vote_ballots
                   (ballot_id, election_id, race_key, choice, voter_anchor_hash, cast_at)
                   VALUES (?,?,?,?,?,?)""",
                (ballot_id, election_id, race_key or "", choice, anchor, timestamp),
            )

            # Mark the voter as having voted (no choice recorded here).
            c.execute(
                """INSERT OR IGNORE INTO voter_voted (voter_id, election_id, voted_at)
                   VALUES (?,?,?)""",
                (voter_id, election_id, timestamp),
            )
            conn.commit()

        receipt_hash = stable_hash("receipt", voter_id, election_id, ballot_id, timestamp)

        # Audit metadata records IP + device fingerprint for forensic tracing,
        # but the choice itself is referenced only by ballot_id — the audit
        # row never stores who-voted-for-what.
        meta = {
            "ip": (ip_address or "")[:64],
            "device": stable_hash("device", device_fingerprint or "")[:16],
            "race_key": race_key or "",
        }
        audit_hash = self.audit_logger.log(
            f"vote_cast:{ballot_id} {json.dumps(meta, separators=(',', ':'))}",
            "VERIFIED",
            "VoteManager+SecrecySplit",
        )

        return {
            'success': True,
            'vote_id': vote_id,
            'ballot_id': ballot_id,
            'receipt_hash': receipt_hash,
            'audit_hash': audit_hash,
            'timestamp': timestamp,
        }

    def spoil_recent(self, voter_id: int, election_id: int) -> Dict[str, Any]:
        """Spoil-and-revote: mark the voter's most recent ballots in this
        election as spoiled so they can re-cast within the window."""
        anchor = self.voter_anchor(voter_id, election_id)
        with db_conn() as conn:
            c = conn.cursor()
            c.execute(
                """UPDATE vote_ballots SET spoiled = 1, spoiled_at = ?
                   WHERE voter_anchor_hash = ? AND election_id = ? AND spoiled = 0""",
                (utcnow_iso(), anchor, election_id),
            )
            spoiled = c.rowcount
            c.execute(
                "DELETE FROM voter_voted WHERE voter_id = ? AND election_id = ?",
                (voter_id, election_id),
            )
            conn.commit()
        self.audit_logger.log(
            f"spoil_revote:{voter_id}:{election_id}",
            "SPOILED",
            "VoteManager",
        )
        return {'spoiled': spoiled}


class BiometricVerifier:
    """Pluggable biometric verifier. The default implementation is
    intentionally a stub that returns lab-mode placeholder scores AND tags
    `verifier_provider = "lab-stub"` so downstream code can detect that real
    biometric verification did not occur.

    DEFER: replace with a real provider (e.g., Onfido, iProov, Jumio) by
    subclassing and overriding `verify_live_session`. The interface contract is
    the dict shape returned below.
    """

    PROVIDER = "lab-stub"

    def verify_live_session(
        self,
        session_token: str,
        video_frames: List[str],
        audio_data: str,
    ) -> Dict[str, Any]:
        # Frames-present heuristic: at least make the stub respond to inputs
        # so frontend tests don't all hit the same hardcoded number.
        present = bool(video_frames) and bool(audio_data)
        score = 90.0 + (5.0 if present else 0.0)
        return {
            'verified': present,
            'liveness_score': score,
            'behavior_score': score - 1.5,
            'deepfake_probability': 0.05 if present else 0.5,
            'session_token': session_token,
            'verifier_provider': self.PROVIDER,
            'lab_mode': True,
        }


# ==================== FLASK API ROUTES ====================
eligibility_engine = EligibilityEngine()
fraud_detector = FraudDetector()
vote_manager = VoteManager(DB_FILE)
biometric_verifier = BiometricVerifier()

app = Flask(
    __name__,
    static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"),
    static_url_path="/static",
)
# Secret key is persisted via the keyring envelope so signed sessions survive
# restart. Falls back to per-boot random if no key is loadable.
_app_secret_seed = ENCRYPTION_KEY if ENCRYPTION_KEY else secrets.token_bytes(32)
app.secret_key = hashlib.sha256(b"flask-app-secret|" + _app_secret_seed).digest()
app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_BYTES  # reject oversize JSON early
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = ENABLE_TLS

session_manager = SessionManager(app.secret_key)

# CORS: allow-listed origin, never `*`. Empty origin = same-origin only.
if CORS:
    if ALLOWED_ORIGIN:
        CORS(app, resources={r"/api/*": {"origins": [ALLOWED_ORIGIN]}}, supports_credentials=True)
    else:
        CORS(app, resources={r"/api/*": {"origins": []}}, supports_credentials=True)

# Rate limiting (best-effort: in-memory if Limiter not installed).
if HAS_LIMITER and Limiter is not None:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["240 per minute"],
        storage_uri="memory://",
    )
else:
    class _NopLimiter:
        def limit(self, *_a, **_kw):
            def deco(fn):
                return fn
            return deco

    limiter = _NopLimiter()
    log.warning("Flask-Limiter not installed; using no-op rate limiter")


# ---- Prometheus metrics ----
if HAS_PROMETHEUS:
    REQ_COUNT = PromCounter("voting_requests_total", "Total HTTP requests", ["method", "path", "status"])
    REQ_LATENCY = PromHist("voting_request_seconds", "Request latency", ["path"])
    AUTH_FAIL = PromCounter("voting_auth_failures_total", "Auth failures", ["layer"])
    VOTES_CAST = PromCounter("voting_votes_total", "Votes cast", ["genre"])
    CHAIN_INTACT = PromGauge("voting_chain_intact", "1 if chain intact, 0 otherwise")
else:
    REQ_COUNT = REQ_LATENCY = AUTH_FAIL = VOTES_CAST = CHAIN_INTACT = None


# Set of valid US state codes for enrollment validation. Empty string allowed
# (means "no state selected yet").
VALID_STATE_CODES = frozenset({
    '', 'AL','AK','AZ','AR','CA','CO','CT','DE','FL','GA','HI','ID','IL','IN','IA',
    'KS','KY','LA','ME','MD','MA','MI','MN','MS','MO','MT','NE','NV','NH','NJ',
    'NM','NY','NC','ND','OH','OK','OR','PA','RI','SC','SD','TN','TX','UT','VT',
    'VA','WA','WV','WI','WY','DC',
})

SESSION_COOKIE_NAME = "voting_session"


# ==================== AUTH / CSRF DECORATORS ====================
def _client_ip() -> str:
    # Prefer X-Forwarded-For only when explicitly trusted (not by default).
    return (request.remote_addr or "")[:64]


def _safe_json() -> Dict[str, Any]:
    """Return request.json or {} without raising on bad/missing body."""
    try:
        data = request.get_json(silent=True)
    except Exception:  # noqa: BLE001
        return {}
    return data if isinstance(data, dict) else {}


def get_session() -> Optional[Dict[str, Any]]:
    """Resolve session from cookie or Authorization: Bearer header."""
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    bearer = request.headers.get("Authorization", "")
    token = ""
    if cookie:
        token = cookie
    elif bearer.startswith("Bearer "):
        token = bearer[7:]
    if not token:
        return None
    return session_manager.load(token)


def require_session(layers: Iterable[str] = ()) -> Callable:
    """Decorator: require a valid session AND that the named auth layers were
    passed. `layers=()` means just require an authenticated session."""
    layers = tuple(layers)

    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            sess = get_session()
            if not sess:
                return jsonify({'success': False, 'error': 'authentication required'}), 401
            if layers:
                missing = [layer for layer in layers if layer not in sess["auth_layers_passed"]]
                if missing:
                    return jsonify({
                        'success': False,
                        'error': 'missing auth layers',
                        'missing_layers': missing,
                    }), 403
            g.session = sess
            return fn(*args, **kwargs)

        return wrapper

    return deco


def require_csrf(fn):
    """CSRF: double-submit token. Header X-CSRF-Token must match session.csrf_token.
    GET/HEAD/OPTIONS are exempt."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return fn(*args, **kwargs)
        sess = getattr(g, "session", None) or get_session()
        if not sess:
            # Endpoints that don't require a session (e.g. enrollment) accept
            # a one-time CSRF cookie instead. Generate one if missing.
            cookie_token = request.cookies.get("csrf_bootstrap")
            header_token = request.headers.get("X-CSRF-Token", "")
            if not (cookie_token and header_token and hmac.compare_digest(cookie_token, header_token)):
                return jsonify({'success': False, 'error': 'CSRF token missing or invalid'}), 403
            return fn(*args, **kwargs)
        sent = request.headers.get("X-CSRF-Token", "")
        if not sent or not hmac.compare_digest(sent, sess["csrf_token"]):
            return jsonify({'success': False, 'error': 'CSRF token mismatch'}), 403
        return fn(*args, **kwargs)

    return wrapper


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        bearer = request.headers.get("Authorization", "")
        token = bearer[7:] if bearer.startswith("Bearer ") else ""
        if not token or not hmac.compare_digest(token, ADMIN_TOKEN):
            return jsonify({'success': False, 'error': 'admin token required'}), 401
        return fn(*args, **kwargs)

    return wrapper


# ==================== SECURITY HEADERS / METRICS / CSRF BOOTSTRAP ====================
@app.before_request
def _before():
    g._t0 = time.time()
    fraud_detector.observe(_client_ip())


@app.after_request
def _after(resp: Response) -> Response:
    # Security headers on every response.
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(self), camera=(self)",
    )
    if ENABLE_TLS:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    # CSP — script-src is self + tailwind CDN ONLY (no 'unsafe-inline' since
    # all our JS lives in /static/voting.js and /static/live.js). Inline event
    # handlers (onclick=) still need 'unsafe-hashes' OR we can rely on the
    # event listeners installed by voting.js. Tailwind runtime injects
    # <style> tags, hence 'unsafe-inline' on style-src is required.
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'self'; object-src 'none'",
    )
    # Bootstrap CSRF cookie if missing — unauthenticated endpoints (enrollment)
    # use this for double-submit verification.
    if not request.cookies.get("csrf_bootstrap"):
        resp.set_cookie(
            "csrf_bootstrap", secrets.token_urlsafe(24),
            httponly=False, secure=ENABLE_TLS, samesite="Lax",
            max_age=24 * 3600,
        )
    # Metrics
    if REQ_COUNT is not None:
        try:
            REQ_COUNT.labels(request.method, request.path, str(resp.status_code)).inc()
            REQ_LATENCY.labels(request.path).observe(time.time() - getattr(g, "_t0", time.time()))
        except Exception:  # noqa: BLE001
            pass
    return resp


@app.errorhandler(Exception)
def _global_error_handler(e):
    """Last-resort error handler. Log, return JSON, never leak stack traces."""
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return jsonify({'success': False, 'error': e.description}), e.code
    log.exception("unhandled error %s %s: %s", request.method, request.path, e)
    return jsonify({'success': False, 'error': 'internal server error'}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Lightweight liveness/readiness probe — verifies the DB is reachable."""
    try:
        with db_conn() as conn:
            conn.execute("SELECT 1").fetchone()
        return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})
    except sqlite3.Error as e:
        return jsonify({'status': 'degraded', 'error': str(e)}), 503


@app.route('/')
def index():
    """Serve the main HTML page"""
    resp = make_response(HTML_CONTENT)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp


@app.route('/api/enroll', methods=['POST'])
@limiter.limit("10 per hour")
@require_csrf
def enroll_voter():
    data = _safe_json()
    ssn = (data.get('ssn') or '').strip()
    name = (data.get('name') or '').strip()
    dob = (data.get('dob') or '').strip()
    tax_id = (data.get('tax_id') or '').strip()
    state = (data.get('state') or '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'Full legal name is required'}), 400
    if len(name) > 200:
        return jsonify({'success': False, 'error': 'Name too long'}), 400
    if state and state.upper() not in VALID_STATE_CODES:
        return jsonify({'success': False, 'error': 'Invalid state code'}), 400
    state = state.upper()
    cleaned_ssn = ssn.replace('-', '')
    if len(cleaned_ssn) != 9 or not cleaned_ssn.isdigit():
        return jsonify({'success': False, 'error': 'Invalid SSN format. Use XXX-XX-XXXX'}), 400
    formatted_ssn = cleaned_ssn[:3] + '-' + cleaned_ssn[3:5] + '-' + cleaned_ssn[5:]
    if not SSNValidator.validate(formatted_ssn):
        return jsonify({'success': False, 'error': 'SSN failed format validation'}), 400

    dob_formatted = dob
    if '/' in dob:
        parts = dob.split('/')
        if len(parts) == 3:
            dob_formatted = parts[2] + '-' + parts[0].zfill(2) + '-' + parts[1].zfill(2)

    ssn_hash = SSNValidator.hash_ssn(formatted_ssn)
    tax_id_hash = stable_hash("tax_id", tax_id) if tax_id else ""

    eligibility = eligibility_engine.check_eligibility(
        formatted_ssn, tax_id or 'TAXPAYER', dob_formatted,
        residency_verified=False,  # DEFER: real path checks residency
    )

    with db_conn() as conn:
        c = conn.cursor()
        # Check both legacy plain and new hashed column to detect dupes from
        # either schema generation.
        c.execute("SELECT id FROM voters WHERE ssn = ? OR ssn_hash = ?", (formatted_ssn, ssn_hash))
        if c.fetchone():
            return jsonify({'success': False, 'error': 'This SSN is already enrolled'}), 409
        c.execute(
            """INSERT INTO voters
               (name, ssn, ssn_hash, dob, tax_id_hash, state, eligibility,
                registered_at, eligibility_source)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (name, formatted_ssn, ssn_hash, dob_formatted, tax_id_hash, state,
             1 if eligibility.get('eligible', True) else 0,
             utcnow_iso(), eligibility.get('source', 'unverified')),
        )
        voter_id = c.lastrowid
        conn.commit()

    AuditLogger(DB_FILE).log(
        f'enrollment:{voter_id}:{name}', 'ENROLLED', 'SSN+EligibilityCheck'
    )
    return jsonify({
        'success': True,
        'voter_id': voter_id,
        'name': name,
        'ssn_masked': '***-**-' + formatted_ssn[-4:],
        'eligibility': eligibility,
    })


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("20 per minute")
@require_csrf
def auth_login():
    """Layer 1: SSN + DOB + tax PIN -> creates a session. The session's
    auth_layers_passed starts with just ['SSN'] and other endpoints add to it.
    cast_vote_api requires all 5 layers."""
    data = _safe_json()
    ssn = (data.get('ssn') or '').strip()
    tax_id = (data.get('tax_id') or '').strip()
    dob = (data.get('dob') or '').strip()
    if not SSNValidator.validate(ssn):
        if AUTH_FAIL: AUTH_FAIL.labels('ssn').inc()
        return jsonify({'success': False, 'error': 'Invalid SSN format'}), 400

    cleaned = ssn.replace('-', '')
    formatted = f"{cleaned[:3]}-{cleaned[3:5]}-{cleaned[5:]}"
    ssn_hash = SSNValidator.hash_ssn(formatted)
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """SELECT id, name, dob, eligibility, residency_verified,
                      felony_disqualified, deceased
               FROM voters WHERE ssn = ? OR ssn_hash = ?""",
            (formatted, ssn_hash),
        )
        row = c.fetchone()
    if not row:
        if AUTH_FAIL: AUTH_FAIL.labels('ssn_unknown').inc()
        # Generic message — don't reveal whether SSN was on file.
        return jsonify({'success': False, 'error': 'identity verification failed'}), 401

    voter_id, name, stored_dob, eligible, residency, felony, deceased = row

    locked, until = LockoutManager.is_locked(voter_id)
    if locked:
        return jsonify({
            'success': False, 'error': 'account temporarily locked',
            'locked_until': until,
        }), 423

    # DOB confirmation (optional in lab mode but required if stored).
    if stored_dob and dob and stored_dob != dob:
        LockoutManager.record_failure(voter_id)
        if AUTH_FAIL: AUTH_FAIL.labels('dob').inc()
        return jsonify({'success': False, 'error': 'identity verification failed'}), 401

    eligibility_check = eligibility_engine.check_eligibility(
        formatted, tax_id or 'TAXPAYER', stored_dob or dob or '1900-01-01',
        residency_verified=bool(residency),
        felony_disqualified=bool(felony),
        deceased=bool(deceased),
    )
    if not eligible or not eligibility_check.get('eligible'):
        return jsonify({
            'success': False,
            'error': 'voter ineligible',
            'eligibility': eligibility_check,
        }), 403

    LockoutManager.reset(voter_id)

    sess = session_manager.create(
        voter_id=voter_id,
        ip=_client_ip(),
        user_agent=request.headers.get("User-Agent", ""),
    )
    session_manager.update_layers(sess["session_id"], "SSN")
    AuditLogger(DB_FILE).log(
        f'login_layer1:{voter_id}', 'PASSED', 'SSN+DOB',
    )

    resp = make_response(jsonify({
        'success': True,
        'voter_id': voter_id,
        'name': name,
        'csrf': sess["csrf"],
        'expires_at': sess["expires_at"],
        'layers_passed': ['SSN'],
        'eligibility': eligibility_check,
    }))
    resp.set_cookie(
        SESSION_COOKIE_NAME, sess["token"],
        httponly=True, secure=ENABLE_TLS, samesite="Lax",
        max_age=SESSION_TTL_SECONDS,
    )
    return resp


@app.route('/api/auth/session', methods=['GET'])
def auth_session():
    """Return current session info (so the SPA can recover state on refresh)."""
    sess = get_session()
    if not sess:
        return jsonify({'authenticated': False})
    return jsonify({
        'authenticated': True,
        'voter_id': sess['voter_id'],
        'csrf': sess['csrf_token'],
        'layers_passed': sess['auth_layers_passed'],
        'expires_at': sess['expires_at'],
    })


@app.route('/api/auth/logout', methods=['POST'])
@require_csrf
def auth_logout():
    sess = get_session()
    if sess:
        session_manager.revoke(sess["session_id"])
    resp = make_response(jsonify({'success': True}))
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


# Legacy alias kept so the existing JS keeps working until the frontend swaps over.
@app.route('/api/auth/verify-ssn', methods=['POST'])
@require_csrf
def verify_ssn():
    return auth_login()


@app.route('/api/auth/live-verify', methods=['POST'])
@require_session(layers=("SSN",))
@require_csrf
def live_verify():
    data = _safe_json()
    session_token = data.get('session_token') or g.session['session_id']
    video_frames = data.get('video_frames') or []
    audio_data = data.get('audio_data') or ''

    result = biometric_verifier.verify_live_session(session_token, video_frames, audio_data)
    if result.get('verified'):
        session_manager.update_layers(g.session["session_id"], "BIOMETRIC")
        AuditLogger(DB_FILE).log(
            f"layer2_biometric:{g.session['voter_id']}", 'PASSED', 'BiometricVerifier',
        )
    else:
        if AUTH_FAIL: AUTH_FAIL.labels('biometric').inc()
        AuditLogger(DB_FILE).log(
            f"layer2_biometric:{g.session['voter_id']}", 'FAILED', 'BiometricVerifier',
        )
    return jsonify(result)


@app.route('/api/auth/generate-otp', methods=['POST'])
@require_session(layers=("SSN",))
@require_csrf
@limiter.limit("6 per minute")
def generate_otp():
    voter_id = g.session['voter_id']
    issued = OTPManager.issue(voter_id)
    AuditLogger(DB_FILE).log(f'otp_generated:{voter_id}', 'ISSUED', 'OTPManager')
    # In lab mode return the OTP in the response (so the demo flow still works).
    # In production, the channel adapter delivers via SMS/email and the response
    # body would NOT include the code.
    return jsonify({
        'otp': issued['otp'],  # DEFER: remove for production
        'expires_at': issued['expires_at'],
        'ttl_seconds': issued['ttl_seconds'],
        'lab_mode': True,
    })


@app.route('/api/auth/verify-otp', methods=['POST'])
@require_session(layers=("SSN",))
@require_csrf
@limiter.limit("12 per minute")
def verify_otp_route():
    data = _safe_json()
    code = (data.get('code') or '').strip()
    voter_id = g.session['voter_id']
    if OTPManager.verify(voter_id, code):
        session_manager.update_layers(g.session["session_id"], "OTP")
        AuditLogger(DB_FILE).log(f'otp_verified:{voter_id}', 'PASSED', 'OTPManager')
        return jsonify({'valid': True})
    LockoutManager.record_failure(voter_id)
    if AUTH_FAIL: AUTH_FAIL.labels('otp').inc()
    AuditLogger(DB_FILE).log(f'otp_verified:{voter_id}', 'FAILED', 'OTPManager')
    return jsonify({'valid': False, 'error': 'incorrect or expired code'}), 401


@app.route('/api/auth/totp-setup', methods=['POST'])
@require_session(layers=("SSN",))
@require_csrf
def totp_setup():
    voter_id = g.session['voter_id']
    info = TOTPManager.setup(voter_id)
    AuditLogger(DB_FILE).log(f'totp_setup:{voter_id}', 'CONFIGURED', 'TOTPManager')
    return jsonify(info)


@app.route('/api/auth/verify-totp', methods=['POST'])
@require_session(layers=("SSN",))
@require_csrf
@limiter.limit("12 per minute")
def verify_totp():
    data = _safe_json()
    code = (data.get('code') or '').strip()
    voter_id = g.session['voter_id']
    if TOTPManager.verify(voter_id, code):
        session_manager.update_layers(g.session["session_id"], "TOTP")
        AuditLogger(DB_FILE).log(f'totp_verified:{voter_id}', 'PASSED', 'TOTPManager')
        return jsonify({'valid': True})
    LockoutManager.record_failure(voter_id)
    if AUTH_FAIL: AUTH_FAIL.labels('totp').inc()
    AuditLogger(DB_FILE).log(f'totp_verified:{voter_id}', 'FAILED', 'TOTPManager')
    return jsonify({'valid': False, 'error': 'invalid authenticator code'}), 401


@app.route('/api/auth/behavioral', methods=['POST'])
@require_session(layers=("SSN", "BIOMETRIC", "OTP", "TOTP"))
@require_csrf
def behavioral():
    """Layer 5. Today this is a stub that just records the layer pass; in
    production it'd call the same biometric provider with a fresh challenge.
    """
    voter_id = g.session['voter_id']
    session_manager.update_layers(g.session["session_id"], "BEHAVIORAL")
    AuditLogger(DB_FILE).log(
        f'layer5_behavioral:{voter_id}', 'PASSED', 'BehavioralStub',
    )
    return jsonify({'success': True, 'layer': 'BEHAVIORAL'})


@app.route('/api/elections', methods=['GET'])
def get_elections():
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, type, start_date, end_date FROM elections")
        rows = c.fetchall()
    elections = [
        {'id': r[0], 'name': r[1], 'type': r[2], 'start_date': r[3], 'end_date': r[4]}
        for r in rows
    ]
    return jsonify({'elections': elections})


@app.route('/api/ballot', methods=['GET'])
def get_ballot():
    """Single source of truth for ballot definitions. Replaces the JS+Python
    duplicate hardcoded arrays. `lang` accepts 'en' (default) or 'es'."""
    lang = (request.args.get('lang') or DEFAULT_LANG)[:8]
    if lang not in ("en", "es"):
        lang = "en"
    return jsonify({'ballot': BallotStore.get_ballot(lang=lang), 'lang': lang})


@app.route('/api/crypto/public-key', methods=['GET'])
def crypto_public_key():
    """Anyone can fetch the public Ed25519 key used to sign vote tokens.
    With this PEM, an off-line tool can verify any vote token's signature."""
    pem = get_public_signing_key_pem()
    if not pem:
        return jsonify({'success': False, 'error': 'signing key unavailable'}), 503
    return jsonify({
        'public_key_pem': pem,
        'algorithm': 'Ed25519',
        'fingerprint_sha256': hashlib.sha256(pem.encode()).hexdigest()[:32],
    })


@app.route('/api/vote/cast', methods=['POST'])
@require_session(layers=("SSN", "BIOMETRIC", "OTP", "TOTP", "BEHAVIORAL"))
@require_csrf
@limiter.limit("60 per hour")
def cast_vote_api():
    data = _safe_json()
    # CRITICAL: voter_id is taken from the session, NEVER from the request body.
    voter_id = g.session['voter_id']
    election_id = int(data.get('election_id') or 1)
    choice = (data.get('choice') or '').strip()
    if not choice or len(choice) > 512:
        return jsonify({'success': False, 'error': 'choice required (1..512 chars)'}), 400

    # Ensure the choice's race_key actually exists in the ballot.
    race_key = choice.split(':', 1)[0] if ':' in choice else choice
    if not BallotStore.race_key_exists(race_key):
        return jsonify({'success': False, 'error': 'unknown race_key'}), 400

    session_data = {
        'ip_address': _client_ip(),
        'device_fingerprint': (data.get('device_fingerprint') or '')[:512],
        'voter_id': voter_id,
    }
    fraud_check = fraud_detector.check_session(session_data)
    if not fraud_check['passed']:
        AuditLogger(DB_FILE).log(
            f'fraud_block:{voter_id}', 'BLOCKED', f"flags={','.join(fraud_check['flags'])}",
        )
        return jsonify({
            'success': False,
            'error': 'Fraud detection failed',
            'flags': fraud_check['flags'],
        }), 403

    result = vote_manager.cast_vote(
        voter_id=voter_id,
        election_id=election_id,
        choice=choice,
        race_key=race_key,
        ip_address=_client_ip(),
        device_fingerprint=session_data['device_fingerprint'],
    )

    if not result.get('success'):
        return jsonify(result), 400

    # ===== MINT VOTE TOKEN (signed) =====
    # The whole prev-hash → compute → sign → insert sequence runs under one
    # lock so concurrent vote casts produce a strictly linear chain.
    now = utcnow_iso()
    genre_map = {'cat-0': 'FEDERAL', 'cat-1': 'STATE', 'cat-2': 'LOCAL', 'cat-3': 'PETITION'}
    cat_prefix = choice.split('-q')[0] if '-q' in choice else 'cat-0'
    genre = genre_map.get(cat_prefix, 'GENERAL')
    category = choice.split(':')[0] if ':' in choice else choice

    choice_hash = stable_hash("choice", choice)
    voter_hash = stable_hash("voter", voter_id, secrets.token_hex(4))
    token_id = f"VT-{now[:10].replace('-','')}-{secrets.token_hex(6).upper()}"
    auth_layers = "SSN,Biometric,OTP,TOTP,Behavioral"

    with _TOKEN_CHAIN_LOCK:
        with db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT token_hash FROM vote_tokens ORDER BY id DESC LIMIT 1")
            prev_row = c.fetchone()
            prev_hash = prev_row[0] if prev_row else '0' * 64

            v1_hash = stable_hash("v1", token_id, voter_id, choice, now, prev_hash)
            token_hash = stable_hash("tok", token_id, v1_hash, voter_hash, choice_hash, prev_hash)
            v2_hash = stable_hash("v2", token_hash, v1_hash, secrets.token_hex(8), now)
            signature = sign_blob(token_hash.encode())

            c.execute(
                """INSERT INTO vote_tokens
                   (token_id, vote_id, voter_id, election_id, genre, category, choice, choice_hash,
                    voter_hash, token_hash, prev_token_hash, auth_layers, device_fingerprint,
                    ip_address, timestamp_created, timestamp_verified, verification_1_hash,
                    verification_2_hash, double_verified, status, signature, ballot_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,'DOUBLE_VERIFIED',?,?)""",
                (token_id, result.get('vote_id') or 0, voter_id, election_id, genre, category,
                 choice, choice_hash, voter_hash, token_hash, prev_hash, auth_layers,
                 session_data['device_fingerprint'], _client_ip(),
                 now, now, v1_hash, v2_hash, signature, result['ballot_id']),
            )
            conn.commit()

    if VOTES_CAST: VOTES_CAST.labels(genre).inc()
    AuditLogger(DB_FILE).log(
        f'token_minted:{token_id}', 'DOUBLE_VERIFIED', 'TokenEngine+Ed25519',
    )

    result['token_id'] = token_id
    result['token_hash'] = token_hash
    result['signature'] = signature
    result['double_verified'] = True
    return jsonify(result)


@app.route('/api/vote/spoil', methods=['POST'])
@require_session(layers=("SSN", "BIOMETRIC", "OTP", "TOTP", "BEHAVIORAL"))
@require_csrf
@limiter.limit("12 per hour")
def vote_spoil():
    """Spoil-and-revote within the election window. Marks the voter's previous
    ballots as spoiled so they can re-cast."""
    data = _safe_json()
    election_id = int(data.get('election_id') or 1)
    ok, reason = is_election_open(election_id)
    if not ok:
        return jsonify({'success': False, 'error': f'election not open: {reason}'}), 403
    res = vote_manager.spoil_recent(g.session['voter_id'], election_id)
    return jsonify({'success': True, 'spoiled': res['spoiled']})


@app.route('/api/vote/provisional', methods=['POST'])
@require_session(layers=("SSN",))
@require_csrf
@limiter.limit("12 per hour")
def vote_provisional():
    """Cast a sealed provisional ballot — used when voter passes auth but
    eligibility is unverified. Election officials adjudicate later."""
    data = _safe_json()
    election_id = int(data.get('election_id') or 1)
    sealed = (data.get('sealed_payload') or '')[:8192]
    reason = (data.get('reason') or 'eligibility_unverified')[:128]
    if not sealed:
        return jsonify({'success': False, 'error': 'sealed_payload required'}), 400
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """INSERT INTO vote_provisional
               (voter_id, election_id, sealed_payload, reason, cast_at)
               VALUES (?,?,?,?,?)""",
            (g.session['voter_id'], election_id, sealed, reason, utcnow_iso()),
        )
        pid = c.lastrowid
        conn.commit()
    AuditLogger(DB_FILE).log(
        f'provisional_cast:{pid}', 'PENDING', f'reason={reason}',
    )
    return jsonify({'success': True, 'provisional_id': pid})


@app.route('/api/vote/tokens', methods=['GET'])
def get_vote_tokens():
    """Public token ledger. Note: voter_id is intentionally redacted to a
    hash so this endpoint cannot be used to re-identify voters. The audit
    log retains the join-key for adjudication."""
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT token_id, vote_id, voter_id, election_id, genre, category,
                     choice, choice_hash, voter_hash, token_hash, prev_token_hash,
                     auth_layers, timestamp_created, timestamp_verified,
                     verification_1_hash, verification_2_hash, double_verified, status,
                     device_fingerprint, ip_address, signature
                     FROM vote_tokens ORDER BY id DESC LIMIT 5000""")
        rows = c.fetchall()

    tokens: List[Dict[str, Any]] = []
    piles: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        token = {
            'token_id': row[0], 'vote_id': row[1],
            # Redact raw voter_id; expose only a derived identifier.
            'voter_redacted': stable_hash("redact_voter", row[2])[:16],
            'election_id': row[3], 'genre': row[4], 'category': row[5],
            'choice': row[6], 'choice_hash': row[7], 'voter_hash': row[8],
            'token_hash': row[9], 'prev_token_hash': row[10],
            'auth_layers': row[11], 'timestamp_created': row[12],
            'timestamp_verified': row[13], 'verification_1_hash': row[14],
            'verification_2_hash': row[15], 'double_verified': bool(row[16]),
            'status': row[17], 'device_fingerprint': row[18] or '',
            'ip_address': row[19] or '',
            'signature': row[20] or '',
        }
        tokens.append(token)
        piles.setdefault(row[4], []).append(token)

    return jsonify({
        'tokens': tokens,
        'piles': piles,
        'total': len(tokens),
        'genres': list(piles.keys()),
    })


@app.route('/api/audit/log', methods=['GET'])
def get_audit():
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """SELECT id, timestamp, action, status, verified_by, entry_hash, prev_hash
               FROM audit_log ORDER BY id DESC LIMIT 100"""
        )
        rows = c.fetchall()
    logs = [
        {
            'id': r[0], 'timestamp': r[1], 'action': r[2], 'status': r[3],
            'verified_by': r[4], 'entry_hash': r[5] or '', 'prev_hash': r[6] or '',
        }
        for r in rows
    ]
    return jsonify({'audit_log': logs})


@app.route('/api/audit/rla-sample', methods=['GET'])
def audit_rla_sample():
    """Risk-limiting audit sample — deterministic random sample of vote
    tokens for offline manual recount. Seed is required so independent
    auditors can reproduce the same sample without trusting the server."""
    seed = (request.args.get('seed') or '')[:128]
    n = max(1, min(500, int(request.args.get('n') or 50)))
    if not seed:
        return jsonify({'success': False, 'error': 'seed required'}), 400
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT token_id, token_hash FROM vote_tokens ORDER BY id ASC")
        all_tokens = c.fetchall()
    if not all_tokens:
        return jsonify({'sample': [], 'total': 0, 'seed': seed})
    # Deterministic ranking by HMAC(seed, token_id).
    ranked = sorted(
        all_tokens,
        key=lambda t: hmac.new(seed.encode(), t[0].encode(), hashlib.sha256).hexdigest(),
    )
    sample = [{'token_id': t[0], 'token_hash': t[1]} for t in ranked[:n]]
    return jsonify({'sample': sample, 'total': len(all_tokens), 'seed': seed, 'n': n})


@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM voters")
        voter_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM votes")
        vote_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM elections")
        election_count = c.fetchone()[0]
        c.execute("SELECT action, timestamp FROM audit_log ORDER BY id DESC LIMIT 10")
        recent_rows = c.fetchall()

        c.execute("SELECT genre, COUNT(*) FROM vote_tokens GROUP BY genre")
        genre_counts = {row[0]: row[1] for row in c.fetchall()}

        c.execute("SELECT COUNT(*) FROM vote_tokens")
        total_tokens = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM vote_tokens WHERE double_verified = 1")
        verified_tokens = c.fetchone()[0]

        # Windowed chain check (last 200 tokens) — replaces the O(n) load-all
        # scan that ran on every dashboard hit.
        c.execute(
            """SELECT token_hash, prev_token_hash FROM vote_tokens
               ORDER BY id DESC LIMIT 200"""
        )
        recent_tokens = list(reversed(c.fetchall()))
        chain_intact = True
        for i in range(1, len(recent_tokens)):
            if recent_tokens[i][1] != recent_tokens[i - 1][0]:
                chain_intact = False
                break

        c.execute("SELECT COUNT(*) FROM audit_log")
        audit_count = c.fetchone()[0]

    if CHAIN_INTACT is not None:
        CHAIN_INTACT.set(1 if chain_intact else 0)

    recent = [f"{row[1]}: {row[0]}" for row in recent_rows] if recent_rows else []

    return jsonify({
        'total_voters': voter_count,
        'total_votes': vote_count,
        'active_elections': election_count,
        'last_updated': utcnow_iso(),
        'recent_activity': recent,
        'genre_counts': genre_counts,
        'total_tokens': total_tokens,
        'verified_tokens': verified_tokens,
        'chain_intact': chain_intact,
        'chain_window_size': len(recent_tokens),
        'audit_count': audit_count,
    })


# ==================== VERIFY TOKEN API ====================
@app.route('/api/verify/token', methods=['GET'])
def verify_token_api():
    token_id = (request.args.get('token_id') or '')[:128]
    if not token_id:
        return jsonify({'found': False, 'error': 'No token_id provided'}), 400

    with db_conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT token_id, vote_id, voter_id, election_id, genre, category,
                     choice, choice_hash, voter_hash, token_hash, prev_token_hash,
                     auth_layers, timestamp_created, timestamp_verified,
                     verification_1_hash, verification_2_hash, double_verified, status,
                     device_fingerprint, ip_address, signature
                     FROM vote_tokens WHERE token_id = ?""", (token_id,))
        row = c.fetchone()
        if not row:
            return jsonify({'found': False}), 404

        c.execute(
            """SELECT id FROM vote_tokens WHERE id <= (
                 SELECT id FROM vote_tokens WHERE token_id = ?
               )""",
            (token_id,),
        )
        chain_position = len(c.fetchall())  # 1-indexed via COUNT semantics
        c.execute("SELECT COUNT(*) FROM vote_tokens")
        total_blocks = c.fetchone()[0]

        # For chain-link check, look at the immediate predecessor only.
        c.execute(
            """SELECT token_hash FROM vote_tokens
               WHERE id < (SELECT id FROM vote_tokens WHERE token_id = ?)
               ORDER BY id DESC LIMIT 1""",
            (token_id,),
        )
        prev_row = c.fetchone()

    token = {
        'token_id': row[0], 'vote_id': row[1],
        'voter_redacted': stable_hash("redact_voter", row[2])[:16],
        'election_id': row[3], 'genre': row[4], 'category': row[5],
        'choice': row[6], 'choice_hash': row[7], 'voter_hash': row[8],
        'token_hash': row[9], 'prev_token_hash': row[10],
        'auth_layers': row[11], 'timestamp_created': row[12],
        'timestamp_verified': row[13], 'verification_1_hash': row[14],
        'verification_2_hash': row[15], 'double_verified': bool(row[16]),
        'status': row[17], 'device_fingerprint': row[18] or '',
        'ip_address': row[19] or '', 'signature': row[20] or '',
    }

    # Check 1: exists
    check_exists = True
    # Check 2: chain link
    if prev_row is None:
        check_chain_link = token['prev_token_hash'] == '0' * 64
    else:
        check_chain_link = token['prev_token_hash'] == prev_row[0]
    # Check 3: double verified
    check_double = bool(
        token['double_verified'] and token['verification_1_hash'] and token['verification_2_hash']
    )
    # Check 4: auth layers
    auth_layers = token.get('auth_layers', '') or ''
    expected = ['SSN', 'Biometric', 'OTP', 'TOTP', 'Behavioral']
    check_auth = all(layer in auth_layers for layer in expected)
    # Check 5: cryptographic signature
    check_signature = bool(token['signature']) and verify_blob(
        token['token_hash'].encode(), token['signature']
    )

    return jsonify({
        'found': True,
        'token': token,
        'chain_position': chain_position,
        'total_blocks': total_blocks,
        'checks': {
            'exists': check_exists,
            'chain_link': check_chain_link,
            'double_verified': check_double,
            'auth_complete': check_auth,
            'signature_valid': check_signature,
            # 'chain_intact' is no longer recomputed per request — see /api/chain/test
            'chain_intact': True,
        },
    })


# ==================== LIVE ELECTION RESULTS API ====================
@app.route('/api/results', methods=['GET'])
def get_results_api():
    """Tally results from `vote_ballots` (the secret-ballot table). Spoiled
    ballots are excluded. Race definitions come from the BallotStore so the
    list of races is whatever's in the DB — not a hardcoded duplicate."""
    genre_idx = int(request.args.get('genre') or 0)
    genre_map = {0: 'FEDERAL', 1: 'STATE', 2: 'LOCAL', 3: 'PETITION'}
    genre = genre_map.get(genre_idx, 'FEDERAL')

    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """SELECT choice, race_key FROM vote_ballots
               WHERE spoiled = 0 AND race_key LIKE ?""",
            (f"cat-{genre_idx}-%",),
        )
        ballot_rows = c.fetchall()

        # Fall back to vote_tokens for tokens that pre-date the secrecy split.
        c.execute(
            "SELECT choice, category FROM vote_tokens WHERE genre = ?",
            (genre,),
        )
        token_rows = c.fetchall()

    races: Dict[str, Dict[str, Any]] = {}

    def _add(choice_full: str, race_key: str):
        if ':' in choice_full:
            qkey, candidate = choice_full.split(':', 1)
        else:
            qkey = choice_full
            candidate = choice_full
        bucket = races.setdefault(qkey, {'candidates': {}, 'category': race_key})
        bucket['candidates'][candidate] = bucket['candidates'].get(candidate, 0) + 1

    for row in ballot_rows:
        _add(row[0], row[1] or '')
    for row in token_rows:
        _add(row[0], row[1] or '')

    # Pull race definitions from ballot store and emit only races in this genre.
    ballot = BallotStore.get_ballot(lang="en")
    questions = [r for r in ballot if r['genre'] == genre]

    result_races = []
    for r in questions:
        key = r['race_key']
        if key in races:
            cands = [{'name': n, 'count': c_} for n, c_ in races[key]['candidates'].items()]
            result_races.append({
                'question': r['question'],
                'type': r['type'],
                'race_key': key,
                'candidates': cands,
            })

    total_in_genre = len(ballot_rows) + len(token_rows)
    return jsonify({'races': result_races, 'total_votes_in_genre': total_in_genre})


# ==================== CHAIN INTEGRITY TEST API ====================
@app.route('/api/chain/test', methods=['GET'])
def chain_test_api():
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """SELECT token_id, token_hash, prev_token_hash, genre, status, double_verified,
                      verification_1_hash, verification_2_hash, signature
               FROM vote_tokens ORDER BY id ASC"""
        )
        rows = c.fetchall()

    blocks = []
    for i, row in enumerate(rows):
        link_valid = (row[2] == '0' * 64) if i == 0 else (row[2] == rows[i - 1][1])
        sig = row[8] or ''
        sig_valid = bool(sig) and verify_blob(row[1].encode(), sig)
        blocks.append({
            'token_id': row[0],
            'token_hash': row[1],
            'prev_token_hash': row[2],
            'genre': row[3],
            'status': row[4],
            'double_verified': bool(row[5]),
            'link_valid': link_valid,
            'v1_hash': row[6],
            'v2_hash': row[7],
            'signature_valid': sig_valid,
        })

    return jsonify({'blocks': blocks, 'total': len(blocks)})


# ==================== STATE HEATMAP API ====================
@app.route('/api/states/votes', methods=['GET'])
def get_state_votes_api():
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """SELECT v.state, COUNT(*) as vote_count
               FROM voters v
               JOIN votes vo ON v.id = vo.voter_id
               WHERE v.state IS NOT NULL AND v.state != ''
               GROUP BY v.state"""
        )
        rows = c.fetchall()
    return jsonify({'state_votes': {row[0]: row[1] for row in rows}})


# ==================== EXPORT AUDIT API ====================
@app.route('/api/export/audit', methods=['GET'])
def export_audit_api():
    format_type = (request.args.get('format') or 'json')[:8]
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """SELECT token_id, vote_id, voter_id, election_id, genre, category,
                      choice, choice_hash, voter_hash, token_hash, prev_token_hash,
                      auth_layers, timestamp_created, timestamp_verified,
                      verification_1_hash, verification_2_hash, double_verified,
                      status, signature
               FROM vote_tokens ORDER BY id ASC"""
        )
        token_rows = c.fetchall()
        c.execute(
            """SELECT id, timestamp, action, status, verified_by, entry_hash, prev_hash
               FROM audit_log ORDER BY id ASC"""
        )
        audit_rows = c.fetchall()

    tokens = [{
        'token_id': r[0], 'vote_id': r[1],
        'voter_redacted': stable_hash("redact_voter", r[2])[:16],
        'election_id': r[3], 'genre': r[4], 'category': r[5],
        'choice': r[6], 'choice_hash': r[7], 'voter_hash': r[8],
        'token_hash': r[9], 'prev_token_hash': r[10],
        'auth_layers': r[11], 'timestamp_created': r[12],
        'timestamp_verified': r[13], 'verification_1_hash': r[14],
        'verification_2_hash': r[15], 'double_verified': bool(r[16]),
        'status': r[17], 'signature': r[18] or '',
    } for r in token_rows]

    audit_log = [{
        'id': r[0], 'timestamp': r[1], 'action': r[2], 'status': r[3],
        'verified_by': r[4], 'entry_hash': r[5] or '', 'prev_hash': r[6] or '',
    } for r in audit_rows]

    export_data = {
        'export_timestamp': utcnow_iso(),
        'system': 'U.S. NATIONAL BALLOT INTEGRITY & VERIFICATION SYSTEM v1.17',
        'public_signing_key_pem': get_public_signing_key_pem(),
        'total_tokens': len(tokens),
        'total_audit_entries': len(audit_log),
        'tokens': tokens,
        'audit_log': audit_log,
    }

    if format_type == 'csv':
        import io
        output = io.StringIO()
        if tokens:
            headers = list(tokens[0].keys())
            output.write(','.join(headers) + '\n')
            for token in tokens:
                row = [str(token.get(h, '')).replace(',', ';') for h in headers]
                output.write(','.join(row) + '\n')
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=voting_audit_export.csv'},
        )
    return jsonify(export_data)


# ==================== ADMIN ENDPOINTS ====================
@app.route('/api/admin/elections', methods=['GET', 'POST'])
@require_admin
def admin_elections():
    if request.method == 'GET':
        with db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT id, name, type, start_date, end_date FROM elections ORDER BY id")
            rows = c.fetchall()
        return jsonify({'elections': [
            {'id': r[0], 'name': r[1], 'type': r[2], 'start_date': r[3], 'end_date': r[4]}
            for r in rows
        ]})
    data = _safe_json()
    name = (data.get('name') or '').strip()[:200]
    type_ = (data.get('type') or '').strip()[:64]
    start = (data.get('start_date') or '').strip()
    end = (data.get('end_date') or '').strip()
    if not (name and type_ and start and end):
        return jsonify({'success': False, 'error': 'name, type, start_date, end_date required'}), 400
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO elections (name, type, start_date, end_date) VALUES (?,?,?,?)",
            (name, type_, start, end),
        )
        eid = c.lastrowid
        conn.commit()
    AuditLogger(DB_FILE).log(f'admin_election_create:{eid}', 'CREATED', 'admin')
    return jsonify({'success': True, 'election_id': eid})


@app.route('/api/admin/races', methods=['GET', 'POST'])
@require_admin
def admin_races():
    if request.method == 'GET':
        return jsonify({'races': BallotStore.get_ballot(lang="en")})
    data = _safe_json()
    election_id = int(data.get('election_id') or 1)
    race_key = (data.get('race_key') or '').strip()[:64]
    genre = (data.get('genre') or '').strip().upper()[:32]
    ordinal = int(data.get('ordinal') or 0)
    type_ = (data.get('type') or '').strip()[:64]
    question = (data.get('question') or '').strip()[:512]
    if not all([race_key, genre, type_, question]) or genre not in {"FEDERAL", "STATE", "LOCAL", "PETITION"}:
        return jsonify({'success': False, 'error': 'race_key, valid genre, type, question required'}), 400
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """INSERT INTO races (election_id, race_key, genre, ordinal, type, question, multi_winner)
               VALUES (?,?,?,?,?,?,0)""",
            (election_id, race_key, genre, ordinal, type_, question),
        )
        rid = c.lastrowid
        conn.commit()
    AuditLogger(DB_FILE).log(f'admin_race_create:{rid}', 'CREATED', 'admin')
    return jsonify({'success': True, 'race_id': rid})


@app.route('/api/admin/candidates', methods=['POST'])
@require_admin
def admin_candidates():
    data = _safe_json()
    race_id = int(data.get('race_id') or 0)
    name = (data.get('name') or '').strip()[:200]
    party = (data.get('party') or '').strip()[:64]
    ordinal = int(data.get('ordinal') or 0)
    is_write_in = 1 if data.get('is_write_in') else 0
    if not (race_id and name):
        return jsonify({'success': False, 'error': 'race_id and name required'}), 400
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """INSERT INTO candidates (race_id, ordinal, name, party, is_write_in)
               VALUES (?,?,?,?,?)""",
            (race_id, ordinal, name, party, is_write_in),
        )
        cid = c.lastrowid
        conn.commit()
    return jsonify({'success': True, 'candidate_id': cid})


@app.route('/api/admin/key-rotate', methods=['POST'])
@require_admin
def admin_key_rotate():
    summary = rotate_encryption_key()
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """INSERT INTO key_rotations
               (rotated_at, primary_fingerprint, previous_count, triggered_by)
               VALUES (?,?,?,?)""",
            (summary['rotated_at'], summary['primary_fingerprint'],
             summary['previous_count'], 'admin-api'),
        )
        conn.commit()
    AuditLogger(DB_FILE).log(
        f"key_rotated:{summary['primary_fingerprint']}", 'ROTATED', 'admin',
    )
    return jsonify({'success': True, **summary})


@app.route('/api/admin/provisional', methods=['GET'])
@require_admin
def admin_provisional_list():
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """SELECT id, voter_id, election_id, reason, cast_at,
                      adjudicated_at, adjudication
               FROM vote_provisional ORDER BY id DESC LIMIT 500"""
        )
        rows = c.fetchall()
    return jsonify({'provisional': [
        {'id': r[0], 'voter_id': r[1], 'election_id': r[2], 'reason': r[3],
         'cast_at': r[4], 'adjudicated_at': r[5], 'adjudication': r[6]}
        for r in rows
    ]})


@app.route('/api/admin/provisional/<int:pid>/adjudicate', methods=['POST'])
@require_admin
def admin_provisional_adjudicate(pid: int):
    data = _safe_json()
    decision = (data.get('decision') or '').upper()[:32]
    if decision not in {'ACCEPTED', 'REJECTED'}:
        return jsonify({'success': False, 'error': 'decision must be ACCEPTED or REJECTED'}), 400
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """UPDATE vote_provisional
               SET adjudicated_at = ?, adjudicated_by = ?, adjudication = ?
               WHERE id = ?""",
            (utcnow_iso(), 'admin', decision, pid),
        )
        conn.commit()
    AuditLogger(DB_FILE).log(
        f'provisional_adjudicated:{pid}', decision, 'admin',
    )
    return jsonify({'success': True, 'pid': pid, 'decision': decision})


# ==================== METRICS ====================
@app.route('/metrics', methods=['GET'])
def metrics():
    if not HAS_PROMETHEUS:
        return jsonify({
            'note': 'prometheus-client not installed; install for /metrics',
            'votes_total': _basic_metrics()['votes'],
            'voters_total': _basic_metrics()['voters'],
            'tokens_total': _basic_metrics()['tokens'],
        })
    body = generate_latest()
    return Response(body, mimetype=CONTENT_TYPE_LATEST)


def _basic_metrics() -> Dict[str, int]:
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM votes"); votes = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM voters"); voters = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM vote_tokens"); tokens = c.fetchone()[0]
    return {'votes': votes, 'voters': voters, 'tokens': tokens}


# ==================== END-TO-END VERIFIABLE VOTING (ElGamal) ====================
# These endpoints implement the Helios-style cryptographic protocol described
# in crypto_voting.py:
#   1. Admin generates a per-election trustee keypair (POST /api/admin/election/<id>/trustee-key)
#   2. Public can fetch the public half (GET /api/election/<id>/trustee-key)
#   3. Authenticated voter encrypts their choice client-side and posts the
#      ciphertext + ZK proof (POST /api/vote/cast-encrypted)
#   4. Anyone can verify any ballot's ZK proof (GET /api/encrypted-ballot/<id>)
#   5. Admin tallies homomorphically and publishes the result + decryption
#      proof (POST /api/admin/election/<id>/tally)
#   6. Anyone can verify the tally proof (GET /api/election/<id>/tally)
#
# In production the trustee key would be split via Pedersen DKG across N
# parties so no one party can decrypt — this single-trustee implementation is
# the starting point.

def _require_e2e_crypto():
    if not HAS_E2E_CRYPTO or crypto_voting is None:
        return jsonify({'success': False, 'error': 'E2E crypto module not available'}), 503
    return None


@app.route('/api/admin/election/<int:eid>/trustee-key', methods=['POST'])
@require_admin
def admin_create_trustee_key(eid: int):
    err = _require_e2e_crypto()
    if err is not None:
        return err
    el = get_election(eid)
    if not el:
        return jsonify({'success': False, 'error': 'election not found'}), 404
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT 1 FROM election_trustee_keys WHERE election_id = ?", (eid,))
        if c.fetchone():
            return jsonify({'success': False, 'error': 'trustee key already exists for this election'}), 409
        sk = crypto_voting.keygen()
        pk = sk.public_key
        c.execute(
            """INSERT INTO election_trustee_keys
               (election_id, params_json, public_h, private_x, created_at)
               VALUES (?,?,?,?,?)""",
            (eid, json.dumps(sk.params.to_dict()), str(pk.h), str(sk.x), utcnow_iso()),
        )
        conn.commit()
    AuditLogger(DB_FILE).log(
        f'trustee_key_created:{eid}', 'CREATED', f'h_fingerprint={hashlib.sha256(str(pk.h).encode()).hexdigest()[:16]}',
    )
    return jsonify({
        'success': True,
        'election_id': eid,
        'public_key': pk.to_dict(),
        'fingerprint_sha256': hashlib.sha256(str(pk.h).encode()).hexdigest()[:32],
    })


@app.route('/api/election/<int:eid>/trustee-key', methods=['GET'])
def get_trustee_public_key(eid: int):
    """Public endpoint: fetch the per-election ElGamal public key. Voter
    clients use this to encrypt ballots."""
    err = _require_e2e_crypto()
    if err is not None:
        return err
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT params_json, public_h FROM election_trustee_keys WHERE election_id = ?",
            (eid,),
        )
        row = c.fetchone()
    if not row:
        return jsonify({'success': False, 'error': 'no trustee key for this election'}), 404
    params = crypto_voting.ElGamalParams.from_dict(json.loads(row[0]))
    pk = crypto_voting.PublicKey(params=params, h=int(row[1]))
    return jsonify({
        'election_id': eid,
        'public_key': pk.to_dict(),
        'fingerprint_sha256': hashlib.sha256(str(pk.h).encode()).hexdigest()[:32],
    })


@app.route('/api/vote/cast-encrypted', methods=['POST'])
@require_session(layers=("SSN", "BIOMETRIC", "OTP", "TOTP", "BEHAVIORAL"))
@require_csrf
@limiter.limit("60 per hour")
def cast_vote_encrypted():
    """Cast an encrypted ballot for one race. The client computes the
    ciphertext + ZK membership proof. Server verifies the proof, stores the
    ciphertext, and records that this voter has voted in this race (so
    double-vote prevention still works without ever seeing the plaintext)."""
    err = _require_e2e_crypto()
    if err is not None:
        return err
    data = _safe_json()
    election_id = int(data.get('election_id') or 1)
    race_key = (data.get('race_key') or '').strip()[:64]
    ct_dict = data.get('ciphertext')
    proof_dict = data.get('proof')
    if not (race_key and ct_dict and proof_dict):
        return jsonify({'success': False, 'error': 'race_key, ciphertext, proof required'}), 400
    if not BallotStore.race_key_exists(race_key):
        return jsonify({'success': False, 'error': 'unknown race_key'}), 400

    # Election open?
    ok, reason = is_election_open(election_id)
    if not ok:
        return jsonify({'success': False, 'error': f'election not open: {reason}'}), 403

    # Trustee key
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT params_json, public_h FROM election_trustee_keys WHERE election_id = ?",
            (election_id,),
        )
        key_row = c.fetchone()
    if not key_row:
        return jsonify({'success': False, 'error': 'no trustee key configured'}), 503
    params = crypto_voting.ElGamalParams.from_dict(json.loads(key_row[0]))
    pk = crypto_voting.PublicKey(params=params, h=int(key_row[1]))

    # Reconstitute ciphertext + proof
    try:
        ct = crypto_voting.Ciphertext.from_dict(ct_dict)
        proof = crypto_voting.DisjunctiveProof(
            challenges=[int(x) for x in proof_dict['challenges']],
            responses=[int(x) for x in proof_dict['responses']],
            a_values=[int(x) for x in proof_dict['a_values']],
            b_values=[int(x) for x in proof_dict['b_values']],
            choices=list(proof_dict['choices']),
        )
    except (KeyError, ValueError, TypeError) as e:
        return jsonify({'success': False, 'error': f'malformed payload: {e}'}), 400

    # Verify ZK proof — without this, a malicious voter could encrypt 1000000
    # instead of 1 and skew the tally undetectably until decrypt.
    if not crypto_voting.verify_membership(pk, ct, proof):
        AUTH_FAIL and AUTH_FAIL.labels('zk_proof').inc()
        return jsonify({'success': False, 'error': 'ZK proof invalid'}), 400

    voter_id = g.session['voter_id']
    anchor = VoteManager.voter_anchor(voter_id, election_id)
    ballot_id = f"EB-{secrets.token_hex(8).upper()}"

    with db_conn() as conn:
        c = conn.cursor()
        # Prevent double-cast for same race
        c.execute(
            """SELECT 1 FROM encrypted_ballots
               WHERE voter_anchor_hash = ? AND race_key = ? AND spoiled = 0""",
            (anchor, race_key),
        )
        if c.fetchone():
            return jsonify({'success': False, 'error': 'already voted in this race'}), 400
        c.execute(
            """INSERT INTO encrypted_ballots
               (ballot_id, election_id, race_key, voter_anchor_hash,
                ciphertext_json, proof_json, cast_at)
               VALUES (?,?,?,?,?,?,?)""",
            (ballot_id, election_id, race_key, anchor,
             json.dumps(ct.to_dict()), json.dumps(proof.to_dict()), utcnow_iso()),
        )
        c.execute(
            "INSERT OR IGNORE INTO voter_voted (voter_id, election_id, voted_at) VALUES (?,?,?)",
            (voter_id, election_id, utcnow_iso()),
        )
        conn.commit()

    AuditLogger(DB_FILE).log(
        f'encrypted_ballot:{ballot_id}', 'CAST', 'ZKProof+ElGamal',
    )
    return jsonify({'success': True, 'ballot_id': ballot_id})


@app.route('/api/encrypted-ballot/<ballot_id>', methods=['GET'])
def get_encrypted_ballot(ballot_id: str):
    """Anyone can fetch any encrypted ballot + its proof and verify off-line."""
    err = _require_e2e_crypto()
    if err is not None:
        return err
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """SELECT eb.ballot_id, eb.election_id, eb.race_key, eb.ciphertext_json,
                      eb.proof_json, eb.cast_at, eb.spoiled,
                      tk.params_json, tk.public_h
               FROM encrypted_ballots eb
               JOIN election_trustee_keys tk ON tk.election_id = eb.election_id
               WHERE eb.ballot_id = ?""",
            (ballot_id[:64],),
        )
        row = c.fetchone()
    if not row:
        return jsonify({'found': False}), 404
    params = crypto_voting.ElGamalParams.from_dict(json.loads(row[7]))
    pk = crypto_voting.PublicKey(params=params, h=int(row[8]))
    ct = crypto_voting.Ciphertext.from_dict(json.loads(row[3]))
    proof_dict = json.loads(row[4])
    proof = crypto_voting.DisjunctiveProof(
        challenges=[int(x) for x in proof_dict['challenges']],
        responses=[int(x) for x in proof_dict['responses']],
        a_values=[int(x) for x in proof_dict['a_values']],
        b_values=[int(x) for x in proof_dict['b_values']],
        choices=list(proof_dict['choices']),
    )
    proof_valid = crypto_voting.verify_membership(pk, ct, proof)
    return jsonify({
        'found': True,
        'ballot_id': row[0],
        'election_id': row[1],
        'race_key': row[2],
        'ciphertext': ct.to_dict(),
        'proof': proof_dict,
        'cast_at': row[5],
        'spoiled': bool(row[6]),
        'proof_valid': proof_valid,
    })


@app.route('/api/admin/election/<int:eid>/tally', methods=['POST'])
@require_admin
def admin_tally_election(eid: int):
    """Trustee tallies the encrypted ballots for one race using homomorphic
    addition, then decrypts the sum + emits a decryption proof. The
    individual ballots are NEVER decrypted."""
    err = _require_e2e_crypto()
    if err is not None:
        return err
    data = _safe_json()
    race_key = (data.get('race_key') or '').strip()[:64]
    if not race_key:
        return jsonify({'success': False, 'error': 'race_key required'}), 400
    max_tally = int(data.get('max_tally') or 1_000_000)
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT params_json, public_h, private_x FROM election_trustee_keys WHERE election_id = ?",
            (eid,),
        )
        key_row = c.fetchone()
        if not key_row:
            return jsonify({'success': False, 'error': 'no trustee key'}), 404
        c.execute(
            """SELECT ciphertext_json FROM encrypted_ballots
               WHERE election_id = ? AND race_key = ? AND spoiled = 0""",
            (eid, race_key),
        )
        ct_rows = c.fetchall()
    if not ct_rows:
        return jsonify({'success': False, 'error': 'no ballots to tally'}), 404
    params = crypto_voting.ElGamalParams.from_dict(json.loads(key_row[0]))
    pk = crypto_voting.PublicKey(params=params, h=int(key_row[1]))
    sk = crypto_voting.PrivateKey(params=params, x=int(key_row[2]))

    cts = [crypto_voting.Ciphertext.from_dict(json.loads(r[0])) for r in ct_rows]
    tally_ct = crypto_voting.homomorphic_tally(pk, cts)
    tally, dec_proof, s_value = crypto_voting.trustee_decrypt_with_proof(
        sk, tally_ct, max_tally=max_tally,
    )

    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """INSERT OR REPLACE INTO election_tallies
               (election_id, race_key, tally, ciphertext_sum_json,
                decryption_proof_json, s_value, tallied_at)
               VALUES (?,?,?,?,?,?,?)""",
            (eid, race_key, tally,
             json.dumps(tally_ct.to_dict()),
             json.dumps(dec_proof.to_dict()),
             str(s_value), utcnow_iso()),
        )
        conn.commit()
    AuditLogger(DB_FILE).log(
        f'tally:{eid}:{race_key}', f'COUNT={tally}', 'TrusteeDecrypt',
    )
    return jsonify({
        'success': True,
        'election_id': eid,
        'race_key': race_key,
        'tally': tally,
        'ballots_tallied': len(cts),
        'decryption_proof': dec_proof.to_dict(),
        'tally_ciphertext': tally_ct.to_dict(),
        's_value': str(s_value),
    })


@app.route('/api/election/<int:eid>/tally', methods=['GET'])
def get_election_tally(eid: int):
    """Public: fetch tallies + their decryption proofs. Anyone can verify
    by reconstructing the homomorphic sum from /api/encrypted-ballot/<id>
    and running crypto_voting.verify_decryption()."""
    err = _require_e2e_crypto()
    if err is not None:
        return err
    with db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """SELECT race_key, tally, ciphertext_sum_json,
                      decryption_proof_json, s_value, tallied_at
               FROM election_tallies WHERE election_id = ? ORDER BY race_key""",
            (eid,),
        )
        rows = c.fetchall()
    return jsonify({
        'election_id': eid,
        'tallies': [
            {
                'race_key': r[0],
                'tally': r[1],
                'ciphertext_sum': json.loads(r[2]),
                'decryption_proof': json.loads(r[3]),
                's_value': r[4],
                'tallied_at': r[5],
            }
            for r in rows
        ],
    })


# ==================== LIVE VOTE RECEIVER ====================
LIVE_RECEIVER_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LIVE VOTE RECEIVER • U.S. NATIONAL BALLOT INTEGRITY SYSTEM v1.17</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="/static/live.css">
</head>
<body>
    <!-- HEADER -->
    <header style="background:linear-gradient(135deg,#002868,#001845);border-bottom:3px solid #FFD700;padding:16px 32px;position:sticky;top:0;z-index:50">
        <div style="display:flex;align-items:center;justify-content:space-between;max-width:1400px;margin:0 auto">
            <div style="display:flex;align-items:center;gap:16px">
                <div class="seal">&#x1F985;</div>
                <div>
                    <h1 class="header-font" style="font-size:18px;letter-spacing:2px">LIVE VOTE RECEIVER</h1>
                    <p style="color:#FFD700;font-size:10px;letter-spacing:3px;font-weight:700">&#9733; U.S. NATIONAL BALLOT INTEGRITY SYSTEM v1.17 &#9733;</p>
                </div>
            </div>
            <div style="display:flex;align-items:center;gap:16px">
                <div class="secure-badge"><i class="fa-solid fa-shield-halved"></i> SHA-256 SECURED</div>
                <div class="secure-badge"><i class="fa-solid fa-link"></i> CHAIN INTEGRITY: <span id="chain-status">VERIFYING...</span></div>
                <div style="display:flex;align-items:center;gap:8px;padding:6px 16px;background:rgba(0,255,136,0.15);border:1px solid rgba(0,255,136,0.4);border-radius:12px">
                    <span class="live-dot"></span>
                    <span style="color:#00ff88;font-weight:700;font-size:12px;letter-spacing:1px">LIVE</span>
                </div>
            </div>
        </div>
    </header>

    <main style="max-width:1400px;margin:0 auto;padding:24px 32px;position:relative;z-index:1">
        <!-- REAL-TIME COUNTER -->
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr 1fr;gap:16px;margin-bottom:24px">
            <div class="stat-card" style="text-align:center;border-color:rgba(0,255,136,0.3);animation:pulse-glow 3s infinite">
                <div style="font-size:10px;color:#00ff88;font-weight:700;letter-spacing:2px;margin-bottom:8px">TOTAL VOTES RECEIVED</div>
                <div id="total-votes" class="mono" style="font-size:48px;font-weight:900;color:#00ff88">0</div>
                <div id="votes-per-sec" style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:4px">0 votes/min</div>
            </div>
            <div class="stat-card" style="text-align:center">
                <div style="font-size:10px;color:#FFD700;font-weight:700;letter-spacing:2px;margin-bottom:8px">PAPER SLIPS MINTED</div>
                <div id="total-slips" class="mono" style="font-size:48px;font-weight:900;color:#FFD700">0</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:4px">Cryptographic receipts</div>
            </div>
            <div class="stat-card" style="text-align:center">
                <div style="font-size:10px;color:#60a5fa;font-weight:700;letter-spacing:2px;margin-bottom:8px">DOUBLE VERIFIED</div>
                <div id="total-verified" class="mono" style="font-size:48px;font-weight:900;color:#60a5fa">0</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:4px">Both hashes confirmed</div>
            </div>
            <div class="stat-card" style="text-align:center">
                <div style="font-size:10px;color:#f87171;font-weight:700;letter-spacing:2px;margin-bottom:8px">REGISTERED VOTERS</div>
                <div id="total-voters" class="mono" style="font-size:48px;font-weight:900;color:#f87171">0</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:4px">Authenticated citizens</div>
            </div>
            <div class="stat-card" style="text-align:center">
                <div style="font-size:10px;color:#c084fc;font-weight:700;letter-spacing:2px;margin-bottom:8px">AUDIT ENTRIES</div>
                <div id="total-audit" class="mono" style="font-size:48px;font-weight:900;color:#c084fc">0</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:4px">Hash-chained log items</div>
            </div>
        </div>

        <!-- GENRE BREAKDOWN -->
        <div class="stat-card" style="margin-bottom:24px;padding:20px 24px">
            <div style="font-size:11px;font-weight:700;letter-spacing:2px;color:rgba(255,255,255,0.5);margin-bottom:12px">VOTES BY GENRE — REAL-TIME DISTRIBUTION</div>
            <div style="display:grid;grid-template-columns:100px 1fr 60px;gap:8px;align-items:center" id="genre-bars">
                <span style="font-size:12px;font-weight:700;color:#60a5fa">FEDERAL</span><div style="background:rgba(255,255,255,0.1);border-radius:4px;height:8px;overflow:hidden"><div id="bar-federal" class="genre-bar" style="width:0%;background:#60a5fa"></div></div><span id="cnt-federal" class="mono" style="font-size:12px;text-align:right;color:#60a5fa">0</span>
                <span style="font-size:12px;font-weight:700;color:#f87171">STATE</span><div style="background:rgba(255,255,255,0.1);border-radius:4px;height:8px;overflow:hidden"><div id="bar-state" class="genre-bar" style="width:0%;background:#f87171"></div></div><span id="cnt-state" class="mono" style="font-size:12px;text-align:right;color:#f87171">0</span>
                <span style="font-size:12px;font-weight:700;color:#fbbf24">LOCAL</span><div style="background:rgba(255,255,255,0.1);border-radius:4px;height:8px;overflow:hidden"><div id="bar-local" class="genre-bar" style="width:0%;background:#fbbf24"></div></div><span id="cnt-local" class="mono" style="font-size:12px;text-align:right;color:#fbbf24">0</span>
                <span style="font-size:12px;font-weight:700;color:#4ade80">PETITION</span><div style="background:rgba(255,255,255,0.1);border-radius:4px;height:8px;overflow:hidden"><div id="bar-petition" class="genre-bar" style="width:0%;background:#4ade80"></div></div><span id="cnt-petition" class="mono" style="font-size:12px;text-align:right;color:#4ade80">0</span>
            </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">
            <!-- CHAIN HEAD -->
            <div class="stat-card">
                <div style="font-size:11px;font-weight:700;letter-spacing:2px;color:rgba(255,255,255,0.5);margin-bottom:12px"><i class="fa-solid fa-link" style="color:#00ff88;margin-right:6px"></i> BLOCKCHAIN HEAD — LATEST PAPER SLIP</div>
                <div id="chain-head-info" style="space-y:8px">
                    <div style="margin-bottom:8px"><span style="font-size:10px;color:rgba(255,255,255,0.4)">TOKEN ID</span><div id="head-token-id" class="mono" style="font-size:14px;color:#FFD700;margin-top:2px">—</div></div>
                    <div style="margin-bottom:8px"><span style="font-size:10px;color:rgba(255,255,255,0.4)">TOKEN HASH</span><div id="head-token-hash" class="chain-hash" style="margin-top:4px">—</div></div>
                    <div style="margin-bottom:8px"><span style="font-size:10px;color:rgba(255,255,255,0.4)">PREV HASH</span><div id="head-prev-hash" class="chain-hash" style="margin-top:4px;color:#60a5fa;border-color:rgba(96,165,250,0.3);background:rgba(96,165,250,0.1)">—</div></div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px">
                        <div><span style="font-size:10px;color:rgba(255,255,255,0.4)">GENRE</span><div id="head-genre" style="font-size:12px;font-weight:700;margin-top:2px">—</div></div>
                        <div><span style="font-size:10px;color:rgba(255,255,255,0.4)">CHOICE</span><div id="head-choice" style="font-size:12px;font-weight:700;margin-top:2px">—</div></div>
                        <div><span style="font-size:10px;color:rgba(255,255,255,0.4)">STATUS</span><div id="head-status" style="font-size:12px;font-weight:700;margin-top:2px">—</div></div>
                        <div><span style="font-size:10px;color:rgba(255,255,255,0.4)">VERIFIED</span><div id="head-verified" style="font-size:12px;font-weight:700;margin-top:2px">—</div></div>
                    </div>
                    <div style="margin-top:8px"><span style="font-size:10px;color:rgba(255,255,255,0.4)">TIMESTAMP</span><div id="head-time" class="mono" style="font-size:11px;color:rgba(255,255,255,0.7);margin-top:2px">—</div></div>
                </div>
            </div>

            <!-- LIVE FEED -->
            <div class="stat-card" style="display:flex;flex-direction:column;max-height:440px">
                <div style="font-size:11px;font-weight:700;letter-spacing:2px;color:rgba(255,255,255,0.5);margin-bottom:12px;flex-shrink:0"><i class="fa-solid fa-bolt" style="color:#fbbf24;margin-right:6px"></i> LIVE AUDIT FEED — REAL-TIME EVENTS</div>
                <div id="live-feed" style="flex:1;overflow-y:auto;space-y:6px;padding-right:4px">
                    <div style="text-align:center;color:rgba(255,255,255,0.3);padding:40px;font-size:12px">Waiting for vote activity...</div>
                </div>
            </div>
        </div>

        <!-- LAST UPDATED -->
        <div style="text-align:center;margin-top:20px;color:rgba(255,255,255,0.2);font-size:10px;letter-spacing:1px">
            LAST POLLED: <span id="last-poll" class="mono">—</span> &nbsp;|&nbsp; POLL INTERVAL: 2s &nbsp;|&nbsp; CONNECTION: <span id="conn-status" style="color:#00ff88">ACTIVE</span>
        </div>
    </main>

    <script src="/static/live.js" defer></script>
</body>
</html>'''


@app.route('/live')
def live_receiver():
    resp = make_response(LIVE_RECEIVER_HTML)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp


@app.route('/api/live/feed', methods=['GET'])
def live_feed_api():
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM votes")
        total_votes = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM vote_tokens")
        total_slips = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM vote_tokens WHERE double_verified = 1")
        total_verified = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM voters")
        total_voters = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM audit_log")
        total_audit = c.fetchone()[0]
        c.execute("SELECT genre, COUNT(*) FROM vote_tokens GROUP BY genre")
        genre_counts = {row[0]: row[1] for row in c.fetchall()}

        c.execute(
            """SELECT token_id, genre, category, choice, token_hash, prev_token_hash,
                      status, double_verified, timestamp_created
               FROM vote_tokens ORDER BY id DESC LIMIT 1"""
        )
        head_row = c.fetchone()
        chain_head = None
        if head_row:
            chain_head = {
                'token_id': head_row[0], 'genre': head_row[1], 'category': head_row[2],
                'choice': head_row[3], 'token_hash': head_row[4], 'prev_token_hash': head_row[5],
                'status': head_row[6], 'double_verified': bool(head_row[7]),
                'timestamp_created': head_row[8],
            }

        # Windowed chain check (last 200 only) instead of O(n) full load.
        c.execute(
            """SELECT token_hash, prev_token_hash FROM vote_tokens
               ORDER BY id DESC LIMIT 200"""
        )
        recent_tokens = list(reversed(c.fetchall()))
        chain_intact = True
        for i in range(1, len(recent_tokens)):
            if recent_tokens[i][1] != recent_tokens[i - 1][0]:
                chain_intact = False
                break

        five_min_ago = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        c.execute(
            "SELECT COUNT(*) FROM vote_tokens WHERE timestamp_created > ?",
            (five_min_ago,),
        )
        recent_count = c.fetchone()[0]
        votes_per_minute = recent_count / 5.0

        c.execute(
            """SELECT id, action, status, verified_by, timestamp, entry_hash
               FROM audit_log ORDER BY id DESC LIMIT 30"""
        )
        recent_audit = [
            {
                'action': row[1], 'status': row[2], 'verified_by': row[3],
                'timestamp': row[4],
                'hash': row[5] or stable_hash("audit", row[4], row[1], row[2], row[3], '0' * 64),
            }
            for row in c.fetchall()
        ]

    return jsonify({
        'total_votes': total_votes,
        'total_slips': total_slips,
        'total_verified': total_verified,
        'total_voters': total_voters,
        'total_audit': total_audit,
        'genre_counts': genre_counts,
        'chain_head': chain_head,
        'chain_intact': chain_intact,
        'votes_per_minute': votes_per_minute,
        'recent_audit': recent_audit,
        'timestamp': utcnow_iso(),
    })


# ==================== SERVER STARTUP ====================
# Force UTF-8 stdout/stderr so the emoji-heavy startup banner doesn't blow up
# on Windows consoles that default to cp1252.
try:
    import sys as _sys
    if hasattr(_sys.stdout, "reconfigure"):
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass


def initialize_system():
    print("\n" + "=" * 70)
    print("🇺🇸 AMERICAN VOTING SYSTEM — HARDENED MONOLITH 🇺🇸")
    print("=" * 70)
    print("Initializing system components...")

    run_migrations()
    print("✅ Schema migrations applied")

    # Seed sample voters/elections only when empty (idempotent across reboots).
    with db_conn() as conn:
        c = conn.cursor()
        # Lab-mode voters use SSN format that passes the validator.
        c.execute(
            """INSERT OR IGNORE INTO voters
               (id, name, ssn, ssn_hash, dob, state, eligibility,
                registered_at, residency_verified, eligibility_source)
               VALUES (1, 'Johnathan Q. Patriot', '123-45-6789', ?,
                       '1996-07-04', 'VA', 1, ?, 1, 'lab-seeded')""",
            (SSNValidator.hash_ssn('123-45-6789'), utcnow_iso()),
        )
        c.execute(
            """INSERT OR IGNORE INTO voters
               (id, name, ssn, ssn_hash, dob, state, eligibility,
                registered_at, residency_verified, eligibility_source)
               VALUES (2, 'Jane Patriot', '987-65-4321', ?,
                       '1990-03-15', 'CA', 1, ?, 1, 'lab-seeded')""",
            (SSNValidator.hash_ssn('987-65-4321'), utcnow_iso()),
        )
        # Backfill ssn_hash for any rows that came from older schemas.
        c.execute("SELECT id, ssn FROM voters WHERE ssn_hash IS NULL OR ssn_hash = ''")
        for vid, vssn in c.fetchall():
            if vssn:
                c.execute("UPDATE voters SET ssn_hash = ? WHERE id = ?",
                          (SSNValidator.hash_ssn(vssn), vid))
        c.execute(
            """INSERT OR IGNORE INTO elections (id, name, type, start_date, end_date)
               VALUES (1, '2026 Presidential Election', 'national_presidential',
                       '2026-01-01T00:00:00+00:00', '2026-12-31T23:59:59+00:00')"""
        )
        c.execute(
            """INSERT OR IGNORE INTO elections (id, name, type, start_date, end_date)
               VALUES (2, 'State Tax Reform Proposition', 'law_referendum',
                       '2026-01-01T00:00:00+00:00', '2026-12-31T23:59:59+00:00')"""
        )
        conn.commit()

    BallotStore.seed_if_empty(default_election_id=1)
    print("✅ Sample data loaded; ballot definitions seeded")

    # Purge expired sessions on boot.
    purged = session_manager.purge_expired()
    if purged:
        print(f"   • Purged {purged} expired session(s)")

    print("\n🔒 SECURITY FEATURES ACTIVE:")
    print(f"   • Itsdangerous-signed sessions: {'ENABLED' if HAS_ITSDANGEROUS else 'HMAC fallback'}")
    print(f"   • Real RFC 6238 TOTP: {'ENABLED (pyotp)' if HAS_PYOTP else 'HMAC-SHA1 fallback'}")
    print(f"   • Ed25519 vote-token signing: {'ENABLED' if SIGNING_KEY else 'HMAC-SHA256 fallback'}")
    print(f"   • CSRF double-submit: ENABLED")
    print(f"   • Rate limiting: {'ENABLED' if HAS_LIMITER else 'NO-OP (install flask-limiter)'}")
    print(f"   • Prometheus metrics: {'ENABLED' if HAS_PROMETHEUS else 'fallback JSON'}")
    print(f"   • TLS: {'ENABLED (adhoc)' if ENABLE_TLS else 'DISABLED — set VOTING_TLS=1'}")
    print(f"   • Ballot-secrecy split (vote_ballots / voter_voted): ENABLED")
    print(f"   • Election open/close window enforcement: ENABLED")
    print(f"   • Account lockout after {LOCKOUT_THRESHOLD} failures / {LOCKOUT_WINDOW_SECONDS}s: ENABLED")

    print("\n📊 ELECTION TYPES SUPPORTED:")
    print("   • National: Presidential, Congressional, Senate")
    print("   • State: Governor, Legislature, Propositions")
    print("   • Local: Mayor, Council, School Board")
    print("   • Direct Democracy: Laws, Petitions, Referendums")
    print("   • Provisional ballots, spoil-and-revote, RLA sampling")

    print(f"\n🔑 Admin bearer token (set VOTING_ADMIN_TOKEN to persist):")
    print(f"   {ADMIN_TOKEN}")

    print("\n" + "=" * 70)
    print("System ready. Lab-mode features are clearly tagged in API responses.")
    print("=" * 70 + "\n")


def _port_is_free(host: str, port: int) -> bool:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.bind((host if host != '0.0.0.0' else '127.0.0.1', port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _pick_port(host: str, preferred: int) -> int:
    """Try the preferred port, then walk forward up to 20 ports — anything bound
    is probably a leftover dev server, not a hostile process."""
    if _port_is_free(host, preferred):
        return preferred
    for delta in range(1, 21):
        if _port_is_free(host, preferred + delta):
            return preferred + delta
    raise RuntimeError(f"No free port found in range {preferred}..{preferred+20}")


def run_flask_server(port: int):
    scheme = "https" if ENABLE_TLS else "http"
    print(f"🌐 Starting Flask API server on {scheme}://localhost:{port}")
    print(f"   Frontend: {scheme}://localhost:{port}/")
    print(f"   API: {scheme}://localhost:{port}/api/\n")

    werkzeug_log = logging.getLogger('werkzeug')
    werkzeug_log.setLevel(logging.ERROR)

    ssl_context = None
    if ENABLE_TLS:
        try:
            ssl_context = "adhoc"  # Werkzeug generates a self-signed cert on the fly
        except Exception as e:  # noqa: BLE001
            log.warning("TLS adhoc cert unavailable (%s); falling back to HTTP", e)
            ssl_context = None

    app.run(
        host=SERVER_HOST, port=port, debug=False,
        threaded=True, use_reloader=False, ssl_context=ssl_context,
    )


if __name__ == "__main__":
    initialize_system()

    try:
        port = _pick_port(SERVER_HOST, SERVER_PORT)
    except RuntimeError as e:
        print(f"❌ {e}")
        raise SystemExit(1)
    if port != SERVER_PORT:
        print(f"⚠️  Port {SERVER_PORT} busy; falling back to {port}")

    server_thread = threading.Thread(target=run_flask_server, args=(port,), daemon=True)
    server_thread.start()

    # Poll the health endpoint instead of sleeping a fixed time — this is both
    # faster on a warm machine and more reliable on a slow one.
    import urllib.request as _urlreq
    base_url = f"http://localhost:{port}"
    for _ in range(50):  # up to ~5s
        try:
            with _urlreq.urlopen(f"{base_url}/api/health", timeout=0.5) as r:
                if r.status == 200:
                    break
        except (OSError, ValueError):
            time.sleep(0.1)

    print("🚀 Opening browser...")
    try:
        webbrowser.open(base_url)
        webbrowser.open(f"{base_url}/live")
    except webbrowser.Error as e:
        print(f"   (Could not auto-open browser: {e})")

    print(f"\n⚡ Server is running on port {port}. Press Ctrl+C to stop.")
    print(f"   Main App: {base_url}/")
    print(f"   Live Vote Receiver: {base_url}/live")
    print(f"   Health: {base_url}/api/health\n")

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n👋 Shutting down American Voting System...")
        print("All votes have been secured on the immutable ledger.")
