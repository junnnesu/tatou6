"""text_overlay_watermark.py

A safe watermarking method that adds a semi-transparent text overlay to PDF pages.
This method uses PyMuPDF (fitz) to safely manipulate PDFs without shell commands.
"""

from __future__ import annotations
from typing import Final
import hashlib
import base64
import json

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class TextOverlayWatermark(WatermarkingMethod):
    """Adds a semi-transparent text watermark to PDF pages."""

    name: Final[str] = "text-overlay"

    # Constants
    _METADATA_KEY: Final[str] = "TextOverlayWatermark"
    
    @staticmethod
    def get_usage() -> str:
        return "Adds a semi-transparent text overlay watermark to PDF pages. Position can be 'top', 'bottom', 'center', 'diagonal' (default: diagonal)."

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Add a text overlay watermark to the PDF."""
        if fitz is None:
            raise WatermarkingError("PyMuPDF (fitz) is required for text overlay watermarking")
            
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        position = (position or "diagonal").lower()
        if position not in ["top", "bottom", "center", "diagonal"]:
            position = "diagonal"

        # Open PDF
        doc = fitz.open(stream=data, filetype="pdf")
        
        # Encode and encrypt the secret
        encrypted_secret = self._encrypt_secret(secret, key)
        
        # Store encrypted secret in document metadata
        metadata = doc.metadata or {}
        metadata[self._METADATA_KEY] = encrypted_secret
        doc.set_metadata(metadata)
        
        # Add visible watermark to each page
        watermark_text = self._generate_watermark_text(secret, key)
        
        for page in doc:
            self._add_text_to_page(page, watermark_text, position)
        
        # Return watermarked PDF
        output = doc.write()
        doc.close()
        return output

    def is_watermark_applicable(
        self,
        pdf,
        position: str | None = None,
    ) -> bool:
        """Check if watermarking is applicable."""
        if fitz is None:
            return False
        try:
            data = load_pdf_bytes(pdf)
            doc = fitz.open(stream=data, filetype="pdf")
            result = doc.page_count > 0
            doc.close()
            return result
        except Exception:
            return False

    def read_secret(self, pdf, key: str) -> str:
        """Extract the secret from the watermarked PDF."""
        if fitz is None:
            raise WatermarkingError("PyMuPDF (fitz) is required for reading watermarks")
            
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
            
        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")
        
        try:
            # Read from metadata
            metadata = doc.metadata or {}
            encrypted_secret = metadata.get(self._METADATA_KEY)
            
            if not encrypted_secret:
                raise SecretNotFoundError("No TextOverlayWatermark found in document")
            
            # Decrypt the secret
            secret = self._decrypt_secret(encrypted_secret, key)
            return secret
            
        finally:
            doc.close()

    # Internal helper methods
    def _encrypt_secret(self, secret: str, key: str) -> str:
        """Simple encryption using XOR with key-derived bytes."""
        # Generate key bytes using SHA256
        key_bytes = hashlib.sha256(key.encode()).digest()
        secret_bytes = secret.encode('utf-8')
        
        # XOR encryption
        encrypted = bytearray()
        for i, byte in enumerate(secret_bytes):
            encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
        
        # Add MAC for authentication
        mac = hashlib.sha256(key.encode() + encrypted).hexdigest()
        
        # Package as JSON
        package = {
            "data": base64.b64encode(encrypted).decode('ascii'),
            "mac": mac
        }
        
        return base64.b64encode(json.dumps(package).encode()).decode('ascii')
    
    def _decrypt_secret(self, encrypted_secret: str, key: str) -> str:
        """Decrypt the secret."""
        try:
            # Decode package
            package = json.loads(base64.b64decode(encrypted_secret))
            encrypted = base64.b64decode(package["data"])
            mac = package["mac"]
            
            # Verify MAC
            expected_mac = hashlib.sha256(key.encode() + encrypted).hexdigest()
            if mac != expected_mac:
                raise InvalidKeyError("Invalid key - MAC verification failed")
            
            # Decrypt using XOR
            key_bytes = hashlib.sha256(key.encode()).digest()
            decrypted = bytearray()
            for i, byte in enumerate(encrypted):
                decrypted.append(byte ^ key_bytes[i % len(key_bytes)])
            
            return decrypted.decode('utf-8')
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise SecretNotFoundError(f"Malformed watermark data: {e}")
    
    def _generate_watermark_text(self, secret: str, key: str) -> str:
        """Generate a short watermark text from secret and key."""
        # Create a hash-based identifier
        combined = f"{secret}:{key}"
        hash_value = hashlib.sha256(combined.encode()).hexdigest()[:8].upper()
        return f"WM-{hash_value}"
    
    def _add_text_to_page(self, page, text: str, position: str):
        """Add watermark text to a page."""
        rect = page.rect
        font_size = 12
        opacity = 0.3
        
        # Create text insertion point based on position
        if position == "top":
            point = fitz.Point(rect.width / 2, 30)
            rotation = 0
        elif position == "bottom":
            point = fitz.Point(rect.width / 2, rect.height - 30)
            rotation = 0
        elif position == "center":
            point = fitz.Point(rect.width / 2, rect.height / 2)
            rotation = 0
        else:  # diagonal
            point = fitz.Point(rect.width / 2, rect.height / 2)
            rotation = 45
        
        # Insert text with transparency
        text_dict = {
            "text": text,
            "fontsize": font_size,
            "rotate": rotation,
            "fill_opacity": opacity,
            "color": (0.5, 0.5, 0.5),  # Gray color
        }
        
        page.insert_text(
            point,
            text,
            fontsize=font_size,
            rotate=rotation,
            color=(0.5, 0.5, 0.5),
            overlay=True
        )


__all__ = ["TextOverlayWatermark"]