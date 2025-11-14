import frappe
import re
import time
from frappe.utils.global_search import search, web_search
from frappe import _

ALLOWED_SEARCH_DOCTYPES = []
DANGEROUS_PATTERN = re.compile(r"[\"'=;`()\+\-\|<>]", re.IGNORECASE)
RATE_LIMIT = 5
TIME_WINDOW = 10

def sanitize_search_input(text):
    if not isinstance(text, str) or len(text) > 20:
        frappe.throw("Invalid search text length.")
    if DANGEROUS_PATTERN.search(text):
        frappe.logger().warning(f"[SECURITY] Rejected input: '{text}' by user {frappe.session.user}")
        # return ("Access denied for this doctype.")
        frappe.throw("Result Not Found")
    if "or" in text.lower() or "1=1" in text.lower():
        frappe.throw("Result Not Found.")

def check_rate_limit(user):
    key = f"search_rate:{user}"
    timestamps = frappe.cache().get(key) or []
    now = int(time.time())
    timestamps = [t for t in timestamps if now - t < TIME_WINDOW]
    if len(timestamps) >= RATE_LIMIT:
        frappe.logger("security").warning(f"[RATE-LIMIT] Too many requests from user: {user}")
        return ("")
        # frappe.throw("Rate limit exceeded. Please wait and try again.")
    timestamps.append(now)
    frappe.cache().set(key, timestamps, TIME_WINDOW)  # Positional arg for expiry



@frappe.whitelist()
def secure_global_search(text, doctype=None, start=0, limit=20):
    user = frappe.session.user

    try:
        sanitize_search_input(text)
        check_rate_limit(user)

        if not doctype or doctype not in ALLOWED_SEARCH_DOCTYPES:
            frappe.logger("security").info(f"[DENIED] User {user} tried accessing invalid doctype: {doctype}")
            return {"results": []}

        if not frappe.has_permission(doctype, "read"):
            frappe.logger("security").info(f"[DENIED] User {user} lacks read permission for {doctype}")
            return {"results": []}

        return search(text=text, doctype=doctype, start=start, limit=limit)

    except Exception as e:
        frappe.logger("security").error(f"[ERROR] Global search failed for user {user}: {str(e)}")
        return {"results": []}


@frappe.whitelist()
def secure_web_search(text, start=0, limit=20):
    user = frappe.session.user

    # Instead of throwing errors, just return empty on invalid input
    try:
        sanitize_search_input(text)
        check_rate_limit(user)
    except Exception as e:
        frappe.logger("security").warning(f"Blocked web search input '{text}' by user {user}: {e}")
        return []

    results = web_search(text=text, start=start, limit=limit)
    
    filtered_results = []
    for r in results:
        dt = r.get("doctype")
        if dt in ALLOWED_SEARCH_DOCTYPES and frappe.has_permission(dt, "read"):
            filtered_results.append(r)
    return filtered_results





ALLOWED_DOCTYPES = ["Need Assesment"]
DANGEROUS_PATTERN = re.compile(r"[\"'=;`()\+\-\|<>]", re.IGNORECASE)

@frappe.whitelist()
def secure_get_count(doctype, filters=None):
    user = frappe.session.user

    if doctype not in ALLOWED_DOCTYPES:
         return _("")
        # frappe.throw(_("You are not allowed to access this doctype."))


    if not frappe.has_permission(doctype, "read", user=user):
        return _("")
        # frappe.throw(_("Not permitted."))

    filters = filters or {}
    return frappe.db.count(doctype, filters=filters)

@frappe.whitelist()
def secure_get_list(doctype, filters=None):
    user = frappe.session.user

    if doctype not in ALLOWED_DOCTYPES:
         return _("")
        # frappe.throw(_("You are not allowed to access this doctype."))

    if not frappe.has_permission(doctype, "read", user=user):
        return _("")
        # frappe.throw(_("Not permitted."))

    filters = filters or {}
    return frappe.db.list(doctype, filters=filters)