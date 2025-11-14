import frappe
import re
import time
from frappe.utils.global_search import search, web_search
from frappe import _

# ============================================================
# CONFIGURATION
# ============================================================

MAX_SEARCH_LENGTH = 100
RATE_LIMIT = 5
TIME_WINDOW = 10  # seconds

# Allow only letters, numbers and spaces (UI searches should be simple)
ALLOWED_SAFE_PATTERN = re.compile(r"^[a-zA-Z0-9 ]+$")

# Blacklist fallback for SQLi payloads
DANGEROUS_PATTERN = re.compile(
    r"("
    r"[\"'`;()<>|&+=-]"                           # SQL control characters
    r"|--"                                        # SQL comment
    r"|\b(or|and|xor|not|select|insert|update|delete|drop|truncate|alter|create|replace)\b"  
    r"|/\*.*?\*/"                                 # Block comments
    r"|#"                                         # Comment
    r"|%[0-9a-fA-F]{2}"                           # Encoded attacks
    r")",
    re.IGNORECASE | re.DOTALL
)

# ============================================================
# LOAD DYNAMIC SETTINGS
# ============================================================

def get_allowed_doctypes():
    """
    Load allowlisted doctypes from 'Global Search Settings'.
    Supports:
    - Table field
    - Comma‑separated string
    - Missing doc / misconfiguration
    """
    try:
        settings = frappe.get_single("Global Search Settings")

        allowed = getattr(settings, "allowed_doctypes", None)

        if not allowed:
            return []

        # Case 1 → list of dict rows
        if isinstance(allowed, list):
            return [row.doctype for row in allowed if getattr(row, "doctype", None)]

        # Case 2 → comma separated text
        if isinstance(allowed, str):
            return [d.strip() for d in allowed.split(",") if d.strip()]

        return []

    except Exception as e:
        frappe.logger("security").warning(f"[SETTINGS] Failed to fetch allowed doctypes: {e}")
        return []


# ============================================================
# INPUT SANITIZATION HELPERS
# ============================================================

def sanitize_string(text: str, field_name="input"):
    """Strictly control any text-based input."""
    if not isinstance(text, str):
        frappe.throw(_(f"Invalid {field_name}"))

    text = text.strip()

    if len(text) == 0 or len(text) > MAX_SEARCH_LENGTH:
        frappe.throw(_(f"{field_name} too long"))

    if not ALLOWED_SAFE_PATTERN.match(text):
        frappe.logger("security").warning(
            f"[SANITIZE] Unsafe {field_name} '{text}' by {frappe.session.user}"
        )
        frappe.throw(_("Result Not Found"))

    if DANGEROUS_PATTERN.search(text):
        frappe.logger("security").warning(
            f"[SANITIZE] SQL injection attempt in {field_name}: '{text}' by {frappe.session.user}"
        )
        frappe.throw(_("Result Not Found"))

    return text


def sanitize_integer(value, field_name="number"):
    """Ensure limit(), start(), etc are strictly integers."""
    try:
        ivalue = int(value)
        if ivalue < 0:
            raise ValueError()
        return ivalue
    except Exception:
        frappe.logger("security").warning(
            f"[SANITIZE] Blocked invalid {field_name} '{value}' by {frappe.session.user}"
        )
        frappe.throw(_(f"Invalid {field_name}"))


def sanitize_filters(filters):
    """Ensures all filter keys and values go through sanitization."""
    if not filters:
        return {}

    if not isinstance(filters, dict):
        print(_("Filters must be a dict"))

    sanitized = {}
    for k, v in filters.items():
        k = sanitize_string(str(k), "filter key")
        v = sanitize_string(str(v), "filter value")
        sanitized[k] = v
    return sanitized


# ============================================================
# RATE LIMITING
# ============================================================

def check_rate_limit(user):
    key = f"search_rate:{user}"
    timestamps = frappe.cache().get(key) or []
    now = int(time.time())

    # Only keep recent timestamps
    timestamps = [t for t in timestamps if now - t < TIME_WINDOW]

    if len(timestamps) >= RATE_LIMIT:
        frappe.logger("security").warning(f"[RATE-LIMIT] Excessive requests by {user}")
        frappe.throw(_("Please wait before searching again."))

    timestamps.append(now)
    frappe.cache().set(key, timestamps, TIME_WINDOW)


# ============================================================
# SECURE GLOBAL SEARCH
# ============================================================

@frappe.whitelist()
def secure_global_search(text, doctype=None, start=0, limit=20):
    user = frappe.session.user

    try:
        text = sanitize_string(text, "text")
        start = sanitize_integer(start, "start")
        limit = sanitize_integer(limit, "limit")
        check_rate_limit(user)

        allowed_search_doctypes = get_allowed_doctypes()

        doctype = sanitize_string(str(doctype or ""), "doctype")

        if not doctype or doctype not in allowed_search_doctypes:
            frappe.logger("security").info(
                f"[DENIED] Doctype not allowed '{doctype}' by {user}"
            )
            return {"results": []}

        if not frappe.has_permission(doctype, "read"):
            frappe.logger("security").info(
                f"[DENIED] Missing read permission for '{doctype}' by {user}"
            )
            return {"results": []}

        return search(text=text, doctype=doctype, start=start, limit=limit)

    except Exception as e:
        frappe.logger("security").error(
            f"[ERROR] secure_global_search failed for {user}: {e}"
        )
        return {"results": []}


# ============================================================
# SECURE WEB SEARCH
# ============================================================

@frappe.whitelist()
def secure_web_search(text, start=0, limit=20):
    user = frappe.session.user

    try:
        text = sanitize_string(text, "text")
        start = sanitize_integer(start, "start")
        limit = sanitize_integer(limit, "limit")
        check_rate_limit(user)

    except Exception as e:
        frappe.logger("security").warning(
            f"[BLOCKED] Web search blocked '{text}' by {user}: {e}"
        )
        return []

    results = web_search(text=text, start=start, limit=limit)
    allowed = get_allowed_doctypes()

    return [
        r for r in results
        if r.get("doctype") in allowed and frappe.has_permission(r.get("doctype"), "read")
    ]


# ============================================================
# SECURE COUNT
# ============================================================

@frappe.whitelist()
def secure_get_count(doctype, filters=None):
    user = frappe.session.user

    try:
        doctype = sanitize_string(str(doctype), "doctype")
        filters = sanitize_filters(filters)
        check_rate_limit(user)

        allowed = get_allowed_doctypes()

        if doctype not in allowed:
            return ""
        if not frappe.has_permission(doctype, "read", user=user):
            return ""

        return frappe.db.count(doctype, filters=filters)

    except Exception as e:
        frappe.logger("security").warning(
            f"[BLOCKED] secure_get_count '{doctype}' by {user}: {e}"
        )
        return ""


# ============================================================
# SECURE LIST
# ============================================================

@frappe.whitelist()
def secure_get_list(doctype, filters=None):
    user = frappe.session.user

    try:
        doctype = sanitize_string(str(doctype), "doctype")
        filters = sanitize_filters(filters)
        check_rate_limit(user)

        allowed = get_allowed_doctypes()

        if doctype not in allowed:
            return []
        if not frappe.has_permission(doctype, "read", user=user):
            return []

        return frappe.db.list(doctype, filters=filters)

    except Exception as e:
        frappe.logger("security").warning(
            f"[BLOCKED] secure_get_list '{doctype}' by {user}: {e}"
        )
        return []
