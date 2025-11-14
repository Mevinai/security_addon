import uuid
from pathlib import Path
from io import BytesIO
from typing import List

import filetype
import frappe
from frappe import _

from pypdf import PdfReader, errors as pdf_errors
from pypdf.errors import PdfStreamError

# -----------------------------
# Dangerous extensions and MIME types
# -----------------------------
DISALLOWED_EXTENSIONS = {
    "php", "php3", "php4", "php5", "php7", "phtml",
    "exe", "dll", "bat", "cmd", "sh", "js", "msi",
    "scr", "pif", "com", "cpl", "jar", "vbs", "vbe",
    "wsf", "wsh", "ps1", "svg"
}

DISALLOWED_MIME_PREFIXES = (
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-sh",
    "application/javascript",
    "application/x-msinstaller",
    "application/x-ms-shortcut",
    "text/x-shellscript",
    "image/svg"
)

# -----------------------------
# Monkey-patch Frappe File.check_content to prevent 500 errors from malformed PDFs
# -----------------------------
from frappe.core.doctype.file.file import File as FrappeFile
original_check_content = FrappeFile.check_content

def safe_check_content(self):
    try:
        original_check_content(self)
    except PdfStreamError:
        frappe.throw(_("Upload blocked: PDF file is corrupted or truncated."), frappe.ValidationError)
    except pdf_errors.PdfReadError:
        frappe.throw(_("Upload blocked: PDF file cannot be read."), frappe.ValidationError)
    except Exception:
        frappe.log_error(frappe.get_traceback(), "PDF Validation Error")
        frappe.throw(_("Upload blocked: invalid PDF file."), frappe.ValidationError)

FrappeFile.check_content = safe_check_content

# -----------------------------
# Helper functions
# -----------------------------
def get_allowed_file_extensions() -> List[str]:
    """
    Returns a clean list of allowed extensions from system settings.
    """
    try:
        allowed = frappe.get_system_settings("allowed_file_extensions") or ""
        return [ext.strip().lower() for ext in allowed.replace("\n", ",").split(",") if ext.strip()]
    except Exception:
        frappe.log_error(frappe.get_traceback(), "Failed to fetch allowed file extensions")
        return []


def pdf_contains_js_safe(file_bytes: bytes) -> bool:
    """
    Safely check if a PDF contains JavaScript.
    Returns False if PDF cannot be parsed, and raises user-friendly errors.
    """
    try:
        reader = PdfReader(BytesIO(file_bytes))
        # Check each page for JavaScript actions (annotations)
        for page in reader.pages:
            annots = page.get("/Annots", [])
            if not annots:
                continue
            for annot in annots:
                obj = annot.get_object()
                if "/JS" in obj or "/Javascript" in obj:
                    return True
        return False
    except (pdf_errors.PdfReadError, PdfStreamError):
        frappe.throw(_("Upload blocked: PDF file is corrupted or truncated."), frappe.ValidationError)
    except Exception:
        frappe.log_error(frappe.get_traceback(), "PDF Validation Error")
        frappe.throw(_("Upload blocked: invalid PDF file."), frappe.ValidationError)

# -----------------------------
# Main validator
# -----------------------------
def validate_uploaded_file(doc, method) -> None:
    """
    Strict file upload validation for Frappe.
    """
    try:
        # 🔐 Block guest users
        if frappe.session.user == "Guest":
            frappe.throw(_("You must be logged in to upload files."), frappe.PermissionError)

        if not doc.file_name:
            return

        file_bytes = doc.get_content()
        if not file_bytes:
            frappe.throw(_("Upload failed: file is empty or unreadable."), frappe.ValidationError)

        # Split filename and check for double extensions
        original_name = Path(doc.file_name).name
        parts = original_name.split(".")
        if len(parts) > 2:
            frappe.throw(_("Upload blocked: filenames cannot contain multiple extensions."), frappe.ValidationError)

        file_ext = parts[-1].lower()

        # Allowed extensions from system settings
        allowed_extensions = get_allowed_file_extensions()
        if not allowed_extensions:
            frappe.throw(_("No allowed file types configured in System Settings."), frappe.ValidationError)

        # Block dangerous extensions anywhere in filename
        for ext in parts:
            if ext.lower() in DISALLOWED_EXTENSIONS:
                frappe.throw(_("Upload blocked: dangerous file extension detected (.{0}).").format(ext), frappe.ValidationError)

        # Detect actual file type
        kind = filetype.guess(file_bytes)
        if kind is None:
            frappe.throw(_("Upload blocked: could not determine file type."), frappe.ValidationError)

        detected_ext = kind.extension.lower()
        detected_mime = kind.mime.lower()

        # Block dangerous MIME types
        if any(detected_mime.startswith(prefix) for prefix in DISALLOWED_MIME_PREFIXES):
            frappe.throw(_("Upload blocked: file type '{0}' is not allowed.").format(detected_mime), frappe.ValidationError)

        # Ensure detected extension is allowed
        if detected_ext not in allowed_extensions:
            frappe.throw(_("Upload blocked: file type '{0}' is not allowed.").format(detected_ext), frappe.ValidationError)

        # Ensure extension matches content
        if file_ext != detected_ext:
            frappe.throw(_("Upload blocked: file extension '.{0}' does not match actual file type '.{1}'.").format(file_ext, detected_ext), frappe.ValidationError)

        # PDF safety: check for embedded JS
        if detected_ext == "pdf":
            if pdf_contains_js_safe(file_bytes):
                frappe.throw(_("Upload blocked: PDF contains embedded JavaScript."), frappe.ValidationError)

        # Rename file server-side for safety
        safe_name = f"{uuid.uuid4()}.{detected_ext}"
        doc.file_name = safe_name

    except frappe.ValidationError:
        raise
    except Exception:
        frappe.log_error(frappe.get_traceback(), "File Upload Validation Error")
        frappe.throw(_("500 : INTERNAL SERVER ERROR. Upload failed due to unexpected error."), frappe.ValidationError)
