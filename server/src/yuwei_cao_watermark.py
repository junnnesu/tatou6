"""yuwei_cao_watermark.py

Yuwei Cao's personal watermarking method for SOFTSEC VT 2025.
This method combines multiple techniques:
1. XMP metadata embedding
2. Zero-width Unicode characters in PDF content
3. Custom object stream with encrypted payload
"""

from __future__ import annotations
from typing import Final
import hashlib
import hmac
import base64
import json
import re
from datetime import datetime

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


class YuweiCaoWatermark(WatermarkingMethod):
    """
    Yuwei Cao's watermarking method using multiple steganographic techniques.
    
    This method embeds secrets in three ways:
    1. XMP metadata (visible but encrypted)
    2. Zero-width Unicode characters (invisible)
    3. Custom PDF object (hidden in structure)
    """

    name: Final[str] = "yuwei-cao-method"
    
    # Constants
    _AUTHOR: Final[str] = "Yuwei Cao"
    _METHOD_ID: Final[str] = "YCW-2025"
    _XMP_NAMESPACE: Final[str] = "http://ns.yuweicao.tatou/1.0/"
    
    # Zero-width Unicode characters for steganography
    _ZERO_WIDTH_CHARS: Final[dict] = {
        '0': '\u200B',  # Zero-width space
        '1': '\u200C',  # Zero-width non-joiner
        '2': '\u200D',  # Zero-width joiner
        '3': '\uFEFF',  # Zero-width no-break space
    }
    
    @staticmethod
    def get_usage() -> str:
        return (
            "Yuwei Cao's advanced watermarking method using XMP metadata, "
            "invisible Unicode characters, and custom PDF objects. "
            "Position can be 'metadata', 'content', 'object', or 'all' (default: all)."
        )
    
    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Add watermark using multiple techniques based on position."""
        if fitz is None:
            raise WatermarkingError("PyMuPDF (fitz) is required for Yuwei Cao's method")
            
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        
        position = (position or "all").lower()
        if position not in ["metadata", "content", "object", "all"]:
            position = "all"
        
        # Open PDF
        doc = fitz.open(stream=data, filetype="pdf")
        
        try:
            # Encrypt the secret
            encrypted_payload = self._encrypt_secret(secret, key)
            
            # Apply watermarking based on position
            if position in ["metadata", "all"]:
                self._embed_in_metadata(doc, encrypted_payload, key)
            
            if position in ["content", "all"]:
                self._embed_in_content(doc, secret, key)
            
            if position in ["object", "all"]:
                self._embed_in_object(doc, encrypted_payload)
            
            # Add author signature
            self._add_signature(doc)
            
            # Return watermarked PDF
            output = doc.write()
            return output
            
        finally:
            doc.close()
    
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
            # Need at least one page for content embedding
            result = doc.page_count > 0
            doc.close()
            return result
        except Exception:
            return False
    
    def read_secret(self, pdf, key: str) -> str:
        """Extract secret from watermarked PDF trying all methods."""
        if fitz is None:
            raise WatermarkingError("PyMuPDF (fitz) is required")
        
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        
        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")
        
        try:
            # Try to read from different locations
            secret = None
            errors = []
            
            # Try metadata first (most reliable)
            try:
                secret = self._extract_from_metadata(doc, key)
                if secret:
                    return secret
            except Exception as e:
                errors.append(f"Metadata: {e}")
            
            # Try content (zero-width chars)
            try:
                secret = self._extract_from_content(doc, key)
                if secret:
                    return secret
            except Exception as e:
                errors.append(f"Content: {e}")
            
            # Try custom object
            try:
                secret = self._extract_from_object(doc, key)
                if secret:
                    return secret
            except Exception as e:
                errors.append(f"Object: {e}")
            
            # If all methods failed
            if errors:
                raise SecretNotFoundError(f"No Yuwei Cao watermark found. Tried: {', '.join(errors)}")
            else:
                raise SecretNotFoundError("No Yuwei Cao watermark found in document")
                
        finally:
            doc.close()
    
    # ===== Embedding Methods =====
    
    def _embed_in_metadata(self, doc, encrypted_payload: str, key: str):
        """Embed encrypted payload in XMP metadata."""
        metadata = doc.metadata or {}
        
        # Create custom metadata fields
        metadata[f"{self._METHOD_ID}_Data"] = encrypted_payload
        metadata[f"{self._METHOD_ID}_Timestamp"] = datetime.utcnow().isoformat()
        metadata[f"{self._METHOD_ID}_Author"] = self._AUTHOR
        metadata[f"{self._METHOD_ID}_Hash"] = self._compute_hash(encrypted_payload, key)
        
        # Also set standard fields
        metadata["Author"] = self._AUTHOR
        metadata["Creator"] = f"Tatou Watermarking System - {self._METHOD_ID}"
        
        doc.set_metadata(metadata)
    
    def _embed_in_content(self, doc, secret: str, key: str):
        """Embed secret using zero-width Unicode characters."""
        if doc.page_count == 0:
            return
        
        # Convert secret to zero-width string
        zero_width_secret = self._encode_zero_width(secret, key)
        
        # Add to first page as invisible text
        page = doc[0]
        
        # Insert at multiple positions for redundancy
        positions = [
            (50, 50),    # Top-left
            (page.rect.width - 50, 50),  # Top-right
            (50, page.rect.height - 50),  # Bottom-left
        ]
        
        for pos in positions:
            # Insert invisible text
            page.insert_text(
                pos,
                zero_width_secret,
                fontsize=1,  # Tiny font
                color=(1, 1, 1),  # White (invisible on white background)
                overlay=True
            )
    
    def _embed_in_object(self, doc, encrypted_payload: str):
        """Embed payload as a custom PDF object."""
        # Create a custom dictionary object with our data
        custom_obj = {
            "Type": f"/{self._METHOD_ID}",
            "Author": self._AUTHOR,
            "Data": encrypted_payload,
            "Created": datetime.utcnow().isoformat(),
            "Version": "1.0"
        }
        
        # Convert to PDF dictionary format
        pdf_dict = self._dict_to_pdf_string(custom_obj)
        
        # This is a simplified approach - in production, you'd properly
        # integrate with PDF structure. For now, we'll add it to metadata
        # as a fallback since PyMuPDF doesn't expose low-level object creation
        metadata = doc.metadata or {}
        metadata[f"{self._METHOD_ID}_Object"] = base64.b64encode(pdf_dict.encode()).decode()
        doc.set_metadata(metadata)
    
    def _add_signature(self, doc):
        """Add author signature to all pages."""
        signature = f"YC-{hashlib.sha256(self._AUTHOR.encode()).hexdigest()[:6]}"
        
        for page in doc:
            # Add tiny signature in corner
            page.insert_text(
                (page.rect.width - 30, page.rect.height - 5),
                signature,
                fontsize=3,
                color=(0.95, 0.95, 0.95),  # Very light gray
                overlay=True
            )
    
    # ===== Extraction Methods =====
    
    def _extract_from_metadata(self, doc, key: str) -> str:
        """Extract secret from metadata."""
        metadata = doc.metadata or {}
        
        # Look for our custom fields
        data_field = f"{self._METHOD_ID}_Data"
        hash_field = f"{self._METHOD_ID}_Hash"
        
        if data_field not in metadata:
            raise SecretNotFoundError("No Yuwei Cao metadata found")
        
        encrypted_payload = metadata[data_field]
        
        # Verify hash if present
        if hash_field in metadata:
            expected_hash = metadata[hash_field]
            actual_hash = self._compute_hash(encrypted_payload, key)
            if expected_hash != actual_hash:
                raise InvalidKeyError("Metadata integrity check failed")
        
        # Decrypt payload
        return self._decrypt_secret(encrypted_payload, key)
    
    def _extract_from_content(self, doc, key: str) -> str:
        """Extract secret from zero-width characters in content."""
        if doc.page_count == 0:
            raise SecretNotFoundError("No pages in document")
        
        # Extract text from first page
        page = doc[0]
        text = page.get_text()
        
        # Find zero-width characters
        zero_width_text = self._extract_zero_width(text)
        
        if not zero_width_text:
            raise SecretNotFoundError("No zero-width characters found")
        
        # Decode the secret
        secret = self._decode_zero_width(zero_width_text, key)
        return secret
    
    def _extract_from_object(self, doc, key: str) -> str:
        """Extract secret from custom object."""
        metadata = doc.metadata or {}
        
        obj_field = f"{self._METHOD_ID}_Object"
        if obj_field not in metadata:
            raise SecretNotFoundError("No custom object found")
        
        # Decode the object data
        obj_data = base64.b64decode(metadata[obj_field]).decode()
        
        # Parse the custom object (simplified)
        if '"Data":' in obj_data:
            # Extract data field
            import re
            match = re.search(r'"Data":\s*"([^"]+)"', obj_data)
            if match:
                encrypted_payload = match.group(1)
                return self._decrypt_secret(encrypted_payload, key)
        
        raise SecretNotFoundError("Could not parse custom object")
    
    # ===== Helper Methods =====
    
    def _encrypt_secret(self, secret: str, key: str) -> str:
        """Encrypt secret with key."""
        # Derive encryption key
        key_bytes = hashlib.pbkdf2_hmac('sha256', key.encode(), b'YuweiCao', 100000)
        
        # XOR encryption (simple but effective for this use case)
        secret_bytes = secret.encode('utf-8')
        encrypted = bytearray()
        
        for i, byte in enumerate(secret_bytes):
            encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
        
        # Add HMAC for authentication
        mac = hmac.new(key.encode(), encrypted, hashlib.sha256).hexdigest()
        
        # Package the data
        package = {
            "author": self._AUTHOR,
            "method": self._METHOD_ID,
            "data": base64.b64encode(encrypted).decode('ascii'),
            "mac": mac
        }
        
        return base64.b64encode(json.dumps(package).encode()).decode('ascii')
    
    def _decrypt_secret(self, encrypted_payload: str, key: str) -> str:
        """Decrypt the secret."""
        try:
            # Unpack the payload
            package = json.loads(base64.b64decode(encrypted_payload))
            
            # Verify author and method
            if package.get("author") != self._AUTHOR:
                raise SecretNotFoundError("Wrong author signature")
            if package.get("method") != self._METHOD_ID:
                raise SecretNotFoundError("Wrong method signature")
            
            # Verify MAC
            encrypted = base64.b64decode(package["data"])
            expected_mac = hmac.new(key.encode(), encrypted, hashlib.sha256).hexdigest()
            if package["mac"] != expected_mac:
                raise InvalidKeyError("MAC verification failed - wrong key")
            
            # Decrypt
            key_bytes = hashlib.pbkdf2_hmac('sha256', key.encode(), b'YuweiCao', 100000)
            decrypted = bytearray()
            
            for i, byte in enumerate(encrypted):
                decrypted.append(byte ^ key_bytes[i % len(key_bytes)])
            
            return decrypted.decode('utf-8')
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise SecretNotFoundError(f"Malformed watermark data: {e}")
    
    def _encode_zero_width(self, text: str, key: str) -> str:
        """Encode text as zero-width characters."""
        # Convert text to base64 for safe encoding
        b64_text = base64.b64encode(text.encode()).decode('ascii')
        
        # Convert to quaternary (base-4) representation
        zero_width = ""
        for char in b64_text:
            # Convert each character to its quaternary representation
            val = ord(char)
            for _ in range(4):  # Each char needs 4 quaternary digits
                zero_width += self._ZERO_WIDTH_CHARS[str(val % 4)]
                val //= 4
        
        # Add markers
        marker = self._ZERO_WIDTH_CHARS['0'] + self._ZERO_WIDTH_CHARS['1'] + \
                self._ZERO_WIDTH_CHARS['2'] + self._ZERO_WIDTH_CHARS['3']
        return marker + zero_width + marker
    
    def _extract_zero_width(self, text: str) -> str:
        """Extract zero-width characters from text."""
        zero_chars = ''.join(self._ZERO_WIDTH_CHARS.values())
        pattern = f"[{re.escape(zero_chars)}]+"
        
        matches = re.findall(pattern, text)
        return ''.join(matches) if matches else ""
    
    def _decode_zero_width(self, zero_width_text: str, key: str) -> str:
        """Decode zero-width characters back to text."""
        # Remove markers
        marker = self._ZERO_WIDTH_CHARS['0'] + self._ZERO_WIDTH_CHARS['1'] + \
                self._ZERO_WIDTH_CHARS['2'] + self._ZERO_WIDTH_CHARS['3']
        
        if zero_width_text.startswith(marker):
            zero_width_text = zero_width_text[len(marker):]
        if zero_width_text.endswith(marker):
            zero_width_text = zero_width_text[:-len(marker)]
        
        # Create reverse mapping
        reverse_map = {v: k for k, v in self._ZERO_WIDTH_CHARS.items()}
        
        # Decode quaternary to base64
        b64_text = ""
        i = 0
        while i < len(zero_width_text):
            val = 0
            for j in range(4):
                if i + j < len(zero_width_text):
                    digit = reverse_map.get(zero_width_text[i + j], '0')
                    val += int(digit) * (4 ** j)
            b64_text += chr(val)
            i += 4
        
        # Decode base64 to original text
        try:
            return base64.b64decode(b64_text).decode('utf-8')
        except Exception:
            raise SecretNotFoundError("Failed to decode zero-width data")
    
    def _compute_hash(self, data: str, key: str) -> str:
        """Compute hash for integrity check."""
        return hmac.new(
            key.encode(),
            f"{self._AUTHOR}:{data}".encode(),
            hashlib.sha256
        ).hexdigest()[:16]
    
    def _dict_to_pdf_string(self, d: dict) -> str:
        """Convert Python dict to PDF dictionary string."""
        items = []
        for k, v in d.items():
            if isinstance(v, str):
                items.append(f"/{k} ({v})")
            else:
                items.append(f"/{k} {v}")
        return f"<< {' '.join(items)} >>"


__all__ = ["YuweiCaoWatermark"]