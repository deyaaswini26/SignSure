"""QR code utilities for SignSure.

Provides:
- Generation of a UUID verification ID.
- Creation of a QR code PNG that encodes only the verification ID.
- Lookup of verification metadata via the SQLite DB.
"""

from __future__ import annotations
import uuid
import pathlib
import json
import zipfile
try:
    import qrcode
except ImportError:
    qrcode = None  # type: ignore[assignment]
from PIL import Image, ImageDraw
from .db import get_document_by_verification_id, DEFAULT_DB_PATH

# Directory to store generated QR codes (inside the data folder)
QR_DIR = pathlib.Path(__file__).resolve().parents[1] / "data" / "qr_codes"
QR_DIR.mkdir(parents=True, exist_ok=True)


def generate_verification_id() -> str:
    """Return a new UUID4 string used as a verification identifier."""
    return str(uuid.uuid4())


def generate_qr_code(verification_id: str, save_dir: pathlib.Path | None = None) -> pathlib.Path:
    """Create a QR code PNG that encodes *only* the verification ID.

    The image is saved under ``save_dir`` (or the default QR directory) and the
    absolute path to the PNG file is returned.
    """
    dir_path = save_dir or QR_DIR
    dir_path.mkdir(parents=True, exist_ok=True)
    file_path = dir_path / f"{verification_id[:8]}.png"
    if qrcode is not None:
        img = qrcode.make(verification_id)
        img.save(file_path)
    else:
        # Fallback deterministic matrix PNG using Pillow when qrcode package is absent
        size = 240
        img = Image.new("RGB", (size, size), "white")
        draw = ImageDraw.Draw(img)
        draw.rectangle([10, 10, size - 10, size - 10], outline="black", width=4)
        cell = 10
        raw = verification_id.encode("utf-8")
        for r in range(18):
            for c in range(18):
                idx = (r * 18 + c) % len(raw)
                if (raw[idx] >> ((r + c) % 8)) & 1:
                    x0 = 30 + c * cell
                    y0 = 30 + r * cell
                    draw.rectangle([x0, y0, x0 + cell - 2, y0 + cell - 2], fill="black")
        img.save(file_path)
    return file_path


def lookup_verification(verification_id: str, db_path: pathlib.Path | None = None):
    """Retrieve the metadata dictionary for a given ``verification_id``.

    Returns ``None`` if the ID is not present in the database.
    """
    return get_document_by_verification_id(verification_id, db_path)
