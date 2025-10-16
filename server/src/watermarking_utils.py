"""watermarking_utils.py

Utility functions and registry for PDF watermarking methods.

This module exposes:

- :data:`METHODS`: a mapping from method name to an instantiated
  :class:`~watermarking_method.WatermarkingMethod`.
- :func:`explore_pdf`: build a lightweight JSON-serializable tree of PDF
  nodes with deterministic identifiers ("name nodes").
- :func:`apply_watermark`: run a concrete watermarking method on a PDF.
- :func:`read_watermark`: recover a secret using a concrete method.
- :func:`register_method` / :func:`get_method`: registry helpers.

Dependencies
------------
Only the standard library is required. If available, the exploration
routine will use *PyMuPDF* (``fitz``) for a richer object inventory. If
``fitz`` is not installed, it gracefully falls back to a permissive
regex-based scan for ``obj ... endobj`` blocks (this may miss compressed
object streams).

To enable the richer exploration, install PyMuPDF:

    pip install pymupdf

"""
from __future__ import annotations

from typing import Any, Dict, Final, Iterable, List, Mapping
import base64
import hashlib
import io
import json
import os
import re

from watermarking_method import (
    PdfSource,
    WatermarkingMethod,
    load_pdf_bytes,
)
from add_after_eof import AddAfterEOF
# Import the safe text overlay method if available
try:
    from text_overlay_watermark import TextOverlayWatermark
    has_text_overlay = True
except ImportError:
    has_text_overlay = False

# Import Yuwei Cao method if available
try:
    from yuwei_cao_watermark import YuweiCaoWatermark
    has_yuwei_method = True
except ImportError:
    has_yuwei_method = False

# Import Yuyuan Su method if available
try:
    from yuyuan_watermarking import WatermarkSafe
    has_yuyuan_method = True
except ImportError:
    has_yuyuan_method = False

# Import Daowei Fu method if available
try:
    from  daowei_fu_watermark import SimpleTextWatermark
    has_daowei_method = True
except ImportError:
    has_daowei_method = False

# --------------------
# Method registry
# --------------------

# Initialize with safe methods only
METHODS: Dict[str, WatermarkingMethod] = {
    AddAfterEOF.name: AddAfterEOF(),
}

# Add text overlay if available
if has_text_overlay:
    METHODS[TextOverlayWatermark.name] = TextOverlayWatermark()

# Add Yuwei Cao method if available
if has_yuwei_method:
    METHODS[YuweiCaoWatermark.name] = YuweiCaoWatermark()

# Add Yuyuan Su method if available
if has_yuyuan_method:
    METHODS[WatermarkSafe.name] = WatermarkSafe()

# Add Daowei Fu method if available
if has_daowei_method:
    METHODS[SimpleTextWatermark.name] = SimpleTextWatermark()

"""Registry of available watermarking methods.

Keys are human-readable method names (stable, lowercase, hyphenated)
exposed by each implementation's ``.name`` attribute. Values are
*instances* of the corresponding class.

NOTE: The unsafe_bash_bridge_append_eof method has been removed for security reasons.
"""


def register_method(method: WatermarkingMethod) -> None:
    """Register (or replace) a watermarking method instance by name.
    
    Note: Be careful when registering methods dynamically as they may
    contain security vulnerabilities.
    """
    # Basic validation to prevent obviously dangerous method names
    if hasattr(method, 'name'):
        method_name = method.name
        # Prevent registration of known unsafe methods
        if 'bash' in method_name.lower() or 'unsafe' in method_name.lower():
            raise ValueError(f"Cannot register potentially unsafe method: {method_name}")
    
    METHODS[method.name] = method


def get_method(method: str | WatermarkingMethod) -> WatermarkingMethod:
    """Resolve a method from a string name or pass-through an instance.

    Raises
    ------
    KeyError
        If ``method`` is a string not present in :data:`METHODS`.
    """
    if isinstance(method, WatermarkingMethod):
        return method
    try:
        return METHODS[method]
    except KeyError as exc:
        raise KeyError(
            f"Unknown watermarking method: {method!r}. Available methods: {sorted(METHODS)}"
        ) from exc


# --------------------
# Public API helpers
# --------------------

def apply_watermark(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes.
    
    Parameters
    ----------
    method : str or WatermarkingMethod
        The watermarking method to use
    pdf : PdfSource
        The source PDF
    secret : str
        The secret to embed
    key : str
        The key for encryption/authentication
    position : str, optional
        Position hint for the watermark
        
    Returns
    -------
    bytes
        The watermarked PDF
    """
    m = get_method(method)
    return m.add_watermark(pdf=pdf, secret=secret, key=key, position=position)


def is_watermarking_applicable(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    position: str | None = None,
) -> bool:
    """Check if a watermarking method is applicable to a PDF.
    
    Parameters
    ----------
    method : str or WatermarkingMethod
        The watermarking method to check
    pdf : PdfSource
        The source PDF
    position : str, optional
        Position hint for the watermark
        
    Returns
    -------
    bool
        True if the method can be applied to this PDF
    """
    m = get_method(method)
    return m.is_watermark_applicable(pdf=pdf, position=position)


def read_watermark(method: str | WatermarkingMethod, pdf: PdfSource, key: str) -> str:
    """Recover a secret from ``pdf`` using the specified method.
    
    Parameters
    ----------
    method : str or WatermarkingMethod
        The watermarking method that was used
    pdf : PdfSource
        The watermarked PDF
    key : str
        The key for decryption/authentication
        
    Returns
    -------
    str
        The recovered secret
    """
    m = get_method(method)
    return m.read_secret(pdf=pdf, key=key)


# --------------------
# PDF exploration
# --------------------

# Pre-compiled regex for the fallback parser (very permissive):
_OBJ_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"(?m)^(\d+)\s+(\d+)\s+obj\b"
)
_ENDOBJ_RE: Final[re.Pattern[bytes]] = re.compile(rb"\bendobj\b")
_TYPE_RE: Final[re.Pattern[bytes]] = re.compile(rb"/Type\s*/([A-Za-z]+)")


def _sha1(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def explore_pdf(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


__all__ = [
    "METHODS",
    "register_method",
    "get_method",
    "apply_watermark",
    "read_watermark",
    "explore_pdf",
    "is_watermarking_applicable"
]