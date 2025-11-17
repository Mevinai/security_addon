# apps/security_addon/security_addon/overrides/password.py

import frappe

def restrict_update_password():
    request_path = frappe.local.request.path
    user = frappe.session.user

    # Only block the /update-password page
    if request_path.startswith("/update-password"):
        # Get the 'key' from query string
        key = frappe.local.request.args.get("key") if frappe.local.request else None

        if not key:
            # No key → redirect to login or block completely
            frappe.throw(
                "This page is disabled. Access requires a valid reset key.",
                frappe.PermissionError
            )

        