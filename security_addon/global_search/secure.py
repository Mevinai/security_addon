import frappe
import re
import time
from frappe.utils.global_search import search, web_search
from frappe import _

ALLOWED_SEARCH_DOCTYPES = ["Need Assesment"]

# Allow only safe characters
ALLOWED_SAFE_PATTERN = re.compile(r"^[a-zA-Z0-9 ]+$")

# Blacklist fallback
DANGEROUS_PATTERN = re.compile(
    r"("
    r"[\"'`;()<>|&+=-]"       
    r"|--"                    
    r"|\b(or|and|xor|not)\b"  
    r"|/\*.*?\*/"             
    r"|#"                     
    r"|%[0-9a-fA-F]{2}"       
    r")",
    re.IGNORECASE | re.DOTALL
)

RATE_LIMIT = 5
TIME_WINDOW = 10


def sanitize_search_input(text):
    if not isinstance(text, str):
        frappe.throw("Invalid search text.")

    if len(text) > 20:
        frappe.throw("Invalid search text length.")

    # Allow-list
    if not ALLOWED_SAFE_PATTERN.match(text):
        frappe.logger("security").warning(f"[SANITIZE] Blocked unsafe input: '{text}' by {frappe.session.user}")
        frappe.throw("Result Not Found")

    # Blacklist extra guard
    if DANGEROUS_PATTERN.search(text):
        frappe.logger("security").warning(f"[SANITIZE] Blocked dangerous input: '{text}' by {frappe.session.user}")
        frappe.throw("Result Not Found")


def check_rate_limit(user):
    key = f"search_rate:{user}"
    timestamps = frappe.cache().get(key) or []
    now = int(time.time())
    timestamps = [t for t in timestamps if now - t < TIME_WINDOW]

    if len(timestamps) >= RATE_LIMIT:
        frappe.logger("security").warning(f"[RATE-LIMIT] Too many search requests from: {user}")
        frappe.throw("Please wait before searching again.")

    timestamps.append(now)
    frappe.cache().set(key, timestamps, TIME_WINDOW)


@frappe.whitelist()
def secure_global_search(text, doctype=None, start=0, limit=20):
    user = frappe.session.user

    try:
        sanitize_search_input(text)
        check_rate_limit(user)

        if not doctype or doctype not in ALLOWED_SEARCH_DOCTYPES:
            frappe.logger("security").info(f"[DENIED] Invalid doctype access by {user}: {doctype}")
            return {"results": []}

        if not frappe.has_permission(doctype, "read"):
            frappe.logger("security").info(f"[DENIED] No read permission for {doctype} by {user}")
            return {"results": []}

        return search(text=text, doctype=doctype, start=start, limit=limit)

    except Exception as e:
        frappe.logger("security").error(f"[ERROR] Global search failed for {user}: {str(e)}")
        return {"results": []}


@frappe.whitelist()
def secure_web_search(text, start=0, limit=20):
    user = frappe.session.user

    try:
        sanitize_search_input(text)
        check_rate_limit(user)
    except Exception as e:
        frappe.logger("security").warning(f"[BLOCKED] Web search input '{text}' by {user}: {e}")
        return []

    results = web_search(text=text, start=start, limit=limit)
    return [
        r for r in results
        if r.get("doctype") in ALLOWED_SEARCH_DOCTYPES
        and frappe.has_permission(r.get("doctype"), "read")
    ]
