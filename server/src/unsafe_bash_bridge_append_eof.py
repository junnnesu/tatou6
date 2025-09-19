"""unsafe_bash_bridge_append_eof.py

Toy watermarking method that appends an authenticated payload *after* the
PDF's final EOF marker but by calling a bash command. Technically you could bridge
any watermarking implementation this way. Don't, unless you know how to sanitize user inputs.

"""
from __future__ import annotations

from typing import Final
import subprocess

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class UnsafeBashBridgeAppendEOF(WatermarkingMethod):
    """Toy method that appends a watermark record after the PDF EOF.

    """

    name: Final[str] = "bash-bridge-eof"

    # ---------------------
    # Public API overrides
    # ---------------------
    
    @staticmethod
    def get_usage() -> str:
        return "Toy method that appends a watermark record after the PDF EOF. Position and key are ignored."

    # Fixed a command injection vulnerability.
    def add_watermark(self, pdf, secret: str, key: str, position: str | None = None) -> bytes:
        pdf_path = Path(pdf)
        if not pdf_path.exists():
            raise FileNotFoundError(f"{pdf_path} not found")

        MAX_READ_BYTES = 200 * 1024 * 1024  # 200 MB
        size = pdf_path.stat().st_size
        if size > MAX_READ_BYTES:
            raise ValueError("file too large")

        with pdf_path.open("rb") as f:
            pdf_bytes = f.read()

        secret_bytes = secret.encode("utf-8")
        result = pdf_bytes + secret_bytes
        return result
        
    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True
    

    def read_secret(self, pdf, key: str) -> str:
        """Extract the secret if present.
           Prints whatever there is after %EOF
        """
        # Fixed a command injection vulnerability.
        marker = b"%EOF"
        tail_limit = 1024 * 1024  # 1 MiB

        with pdf.open("rb") as f:
            f.seek(0, 2)
            file_size = f.tell()
            if file_size == 0:
                res_stdout = ""
            else:
                read_size = min(file_size, tail_limit)
                f.seek(file_size - read_size)
                data = f.read(read_size)
                idx = data.rfind(marker)
                if idx != -1:
                    after_bytes = data[idx + len(marker):]
                else:
                    after_bytes = b""
                res_stdout = after_bytes.decode("utf-8", errors="replace")
       

        return res.stdout



__all__ = ["UnsafeBashBridgeAppendEOF"]

