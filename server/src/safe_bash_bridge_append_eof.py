"""safe_bash_bridge_append_eof.py

安全版本的 EOF 追加水印方法
原本使用危险的 shell 命令，现在改为纯 Python 实现
保持相同的方法名以确保向后兼容性
"""
from __future__ import annotations

from typing import Final
import base64

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class SafeBashBridgeAppendEOF(WatermarkingMethod):
    """安全版本的 EOF 追加水印方法
    
    此方法在 PDF 文件的 %%EOF 标记后追加水印数据。
    与原始的不安全版本不同，这个实现：
    - 不使用任何 shell 命令
    - 不会受到命令注入攻击
    - 纯 Python 实现，更安全可靠
    
    水印格式:
    <original PDF>%%EOF
    %%WATERMARK-SAFE-V1
    <base64 encoded secret>
    """

    name: Final[str] = "bash-bridge-eof"  # 保持原名称以兼容
    
    # 水印标记
    _MARKER: Final[bytes] = b"\n%%WATERMARK-SAFE-V1\n"

    @staticmethod
    def get_usage() -> str:
        return "Safe method that appends a watermark record after the PDF EOF. Position and key are ignored."

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """在 PDF 的 EOF 标记后安全地追加水印
        
        Parameters
        ----------
        pdf : PdfSource
            输入的 PDF 文件
        secret : str
            要嵌入的秘密信息
        key : str
            密钥（在这个简单实现中被忽略，但保留参数以兼容）
        position : str | None
            位置（被忽略）
            
        Returns
        -------
        bytes
            带水印的 PDF 数据
        """
        # 验证输入
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(secret, str):
            raise ValueError("Secret must be a string")
            
        # 加载 PDF 数据
        data = load_pdf_bytes(pdf)
        
        # 查找 %%EOF 标记
        eof_index = data.rfind(b'%%EOF')
        if eof_index == -1:
            # 如果没找到 EOF，直接追加到末尾
            # （某些 PDF 可能没有正确的 EOF 标记）
            if not data.endswith(b'\n'):
                data += b'\n'
            data += b'%%EOF\n'
        
        # 对 secret 进行 base64 编码（避免特殊字符问题）
        encoded_secret = base64.b64encode(secret.encode('utf-8'))
        
        # 构建水印数据
        watermark = self._MARKER + encoded_secret + b'\n'
        
        # 追加水印到 PDF 末尾
        return data + watermark
        
    def is_watermark_applicable(
        self,
        pdf,
        position: str | None = None,
    ) -> bool:
        """检查是否可以应用此水印方法
        
        这个方法总是返回 True，因为我们可以在任何 PDF 后追加数据
        """
        try:
            data = load_pdf_bytes(pdf)
            return len(data) > 0
        except Exception:
            return False

    def read_secret(self, pdf, key: str) -> str:
        """从 PDF 中提取水印信息
        
        Parameters
        ----------
        pdf : PdfSource
            可能包含水印的 PDF 文件
        key : str
            密钥（在这个简单实现中被忽略）
            
        Returns
        -------
        str
            提取出的秘密信息
            
        Raises
        ------
        SecretNotFoundError
            如果没有找到水印
        """
        data = load_pdf_bytes(pdf)
        
        # 查找水印标记
        marker_index = data.rfind(self._MARKER)
        if marker_index == -1:
            # 为了兼容旧版本，也尝试查找没有标记的情况
            # 查找 %%EOF 后的内容
            eof_index = data.rfind(b'%%EOF')
            if eof_index == -1:
                raise SecretNotFoundError("No EOF marker found in PDF")
            
            # 读取 EOF 后的内容
            after_eof = data[eof_index + 5:].strip()
            if not after_eof:
                raise SecretNotFoundError("No watermark found after EOF")
            
            # 尝试直接解码（兼容旧版本）
            try:
                return after_eof.decode('utf-8')
            except UnicodeDecodeError:
                # 如果解码失败，尝试 base64 解码
                try:
                    return base64.b64decode(after_eof).decode('utf-8')
                except Exception:
                    raise SecretNotFoundError("Unable to decode watermark")
        
        # 找到了新版本的标记
        start = marker_index + len(self._MARKER)
        
        # 查找水印数据的结束位置（到下一个换行符或文件末尾）
        end = data.find(b'\n', start)
        if end == -1:
            end = len(data)
        
        # 提取 base64 编码的数据
        encoded_secret = data[start:end].strip()
        if not encoded_secret:
            raise SecretNotFoundError("Empty watermark data")
        
        # 解码 base64
        try:
            decoded = base64.b64decode(encoded_secret)
            return decoded.decode('utf-8')
        except Exception as e:
            raise SecretNotFoundError(f"Failed to decode watermark: {e}")


__all__ = ["SafeBashBridgeAppendEOF"]