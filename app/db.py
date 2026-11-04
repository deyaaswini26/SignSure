"""Database utilities for SignSure.

Provides a small SQLite wrapper with three tables:

* ``documents`` – records of signed PDFs.
* ``trusted_signers`` – registry of public keys that the system trusts.
* ``verification_logs`` – history of verification attempts.

All functions raise ``sqlite3.IntegrityError`` for constraint violations and
``Exception`` for unexpected errors.  ``init_db`` creates the tables if they do
not already exist.
"""






import sqlite3
import datetime
import pathlib
from typing import Optional, List, Dict, Any

# Helper function to revoke a signer
def revoke_trusted_signer(signer_id: int, db_path: Optional[pathlib.Path] = None) -> None:
    """Set trust_status='revoked' for the given signer.
    """
    conn = _get_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE trusted_signers SET trust_status = 'revoked' WHERE signer_id = ?
            """,
            (signer_id,)
        )
        conn.commit()
    finally:
        conn.close()

# Helper to fetch verification logs for a document
def get_verification_logs(document_id: int, db_path: Optional[pathlib.Path] = None) -> List[Dict[str, Any]]:
    conn = _get_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM verification_logs WHERE document_id = ? ORDER BY verification_timestamp DESC",
            (document_id,)
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()

# Stats helpers
def get_stats(db_path: Optional[pathlib.Path] = None) -> Dict[str, int]:
    conn = _get_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM documents")
        total_docs = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM verification_logs")
        total_verifs = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM verification_logs WHERE verification_result = 1")
        successful = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM verification_logs WHERE verification_result = 0")
        failed = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM trusted_signers WHERE trust_status = 'trusted'")
        trusted = cur.fetchone()[0]
        return {
            "total_documents": total_docs,
            "total_verifications": total_verifs,
            "successful_verifications": successful,
            "failed_verifications": failed,
            "trusted_signers": trusted,
        }
    finally:
        conn.close()




from typing import Optional, List, Dict, Any, Dict, List, Any

# Default location of the SQLite database file (inside the ``data`` folder).
DEFAULT_DB_PATH = pathlib.Path(__file__).resolve().parents[1] / "data" / "signsure.db"


def _get_connection(db_path: Optional[pathlib.Path] = None) -> sqlite3.Connection:
    """Return a SQLite connection.

    Args:
        db_path: Optional custom path – used by the test suite.  If ``None``,
            ``DEFAULT_DB_PATH`` is used.
    """
    path = db_path or DEFAULT_DB_PATH
    # Ensure the parent directory exists.
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[pathlib.Path] = None) -> None:
    """Create tables if they do not exist.

    This function is idempotent – calling it multiple times is safe.
    """
    conn = _get_connection(db_path)
    try:
        cur = conn.cursor()
        # ``documents`` table stores a record for each signed package.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS documents (
                document_id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_filename TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                signing_timestamp TEXT NOT NULL,
                verification_id TEXT NOT NULL UNIQUE,
                public_key_fingerprint TEXT NOT NULL,
                verification_status TEXT NOT NULL
            );
            """
        )
        # ``trusted_signers`` stores public keys that the system trusts.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS trusted_signers (
                signer_id INTEGER PRIMARY KEY AUTOINCREMENT,
                signer_name TEXT NOT NULL,
                public_key BLOB NOT NULL,
                public_key_fingerprint TEXT NOT NULL UNIQUE,
                registration_timestamp TEXT NOT NULL,
                trust_status TEXT NOT NULL CHECK(trust_status IN ('trusted','revoked'))
            );
            """
        )
        # ``verification_logs`` stores each verification attempt.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS verification_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                verification_id TEXT NOT NULL,
                document_id INTEGER NOT NULL,
                verification_timestamp TEXT NOT NULL,
                verification_result INTEGER NOT NULL CHECK(verification_result IN (0,1)),
                failure_reason TEXT,
                FOREIGN KEY(document_id) REFERENCES documents(document_id)
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Document handling
# ---------------------------------------------------------------------------

def add_document(
    original_filename: str,
    sha256_hash: str,
    signing_timestamp: str,
    verification_id: str,
    public_key_fingerprint: str,
    verification_status: str = "signed",
    db_path: Optional[pathlib.Path] = None,
) -> int:
    """Insert a document record and return its ``document_id``.

    ``verification_status`` can be ``signed``, ``verified`` or any custom label.
    """
    conn = _get_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO documents (
                original_filename, sha256_hash, signing_timestamp,
                verification_id, public_key_fingerprint, verification_status
            ) VALUES (?,?,?,?,?,?)
            """,
            (
                original_filename,
                sha256_hash,
                signing_timestamp,
                verification_id,
                public_key_fingerprint,
                verification_status,
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_document_by_verification_id(
    verification_id: str, db_path: Optional[pathlib.Path] = None
) -> Optional[Dict[str, Any]]:
    """Return a document row as a dict, or ``None`` if not found."""
    conn = _get_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM documents WHERE verification_id = ?",
            (verification_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_documents(db_path: Optional[pathlib.Path] = None) -> List[Dict[str, Any]]:
    """Return all document rows ordered by signing timestamp descending."""
    conn = _get_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM documents ORDER BY signing_timestamp DESC")
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Trusted signer registry
# ---------------------------------------------------------------------------

def register_trusted_signer(
    signer_name: str,
    public_key_pem: bytes,
    trust_status: str = "trusted",
    db_path: Optional[pathlib.Path] = None,
) -> int:
    """Add a signer to the trusted registry.

    Returns the generated ``signer_id``.
    """
    fingerprint = _fingerprint(public_key_pem)
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    conn = _get_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO trusted_signers (
                signer_name, public_key, public_key_fingerprint,
                registration_timestamp, trust_status
            ) VALUES (?,?,?,?,?)
            """,
            (signer_name, public_key_pem, fingerprint, timestamp, trust_status),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_trusted_signer_by_fingerprint(
    fingerprint: str, db_path: Optional[pathlib.Path] = None
) -> Optional[Dict[str, Any]]:
    conn = _get_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM trusted_signers WHERE public_key_fingerprint = ? AND trust_status = 'trusted'",
            (fingerprint,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def is_signer_trusted(fingerprint: str, db_path: Optional[pathlib.Path] = None) -> bool:
    return get_trusted_signer_by_fingerprint(fingerprint, db_path) is not None


# ---------------------------------------------------------------------------
# Verification logging
# ---------------------------------------------------------------------------

def record_verification(
    verification_id: str,
    document_id: int,
    result: bool,
    failure_reason: Optional[str] = None,
    db_path: Optional[pathlib.Path] = None,
) -> int:
    """Insert a verification attempt.

    ``result`` is ``True`` for a successful verification, ``False`` otherwise.
    Returns the generated ``log_id``.
    """
    conn = _get_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO verification_logs (
                verification_id, document_id, verification_timestamp,
                verification_result, failure_reason
            ) VALUES (?,?,?,?,?)
            """,
            (
                verification_id,
                document_id,
                datetime.datetime.utcnow().isoformat() + "Z",
                1 if result else 0,
                failure_reason,
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Helper functions (internal)
# ---------------------------------------------------------------------------

def _fingerprint(public_pem: bytes) -> str:
    """Calculate the SHA‑256 hex fingerprint of a PEM‑encoded public key."""
    from .crypto import sha256_digest

    return sha256_digest(public_pem).hex()


# Re‑export constants for convenience
__all__ = [
    "init_db",
    "add_document",
    "get_document_by_verification_id",
    "list_documents",
    "register_trusted_signer",
    "get_trusted_signer_by_fingerprint",
    "is_signer_trusted",
    "record_verification",
    "DEFAULT_DB_PATH",
]
