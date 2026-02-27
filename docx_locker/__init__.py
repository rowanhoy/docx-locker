from .docx_locker import (
    apply_docx_protection,
    apply_docx_protection_buffer,
    get_docx_protection,
    is_protected,
    remove_docx_protection,
    remove_docx_protection_buffer,
    DocxProtectionParams,
)

__all__ = [
    "apply_docx_protection",
    "apply_docx_protection_buffer",
    "get_docx_protection",
    "is_protected",
    "remove_docx_protection",
    "remove_docx_protection_buffer",
    "DocxProtectionParams",
]

__version__ = "0.7.2"
