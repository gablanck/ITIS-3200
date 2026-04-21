# app.py — Main Flask application for the Smart Home Security Dashboard
#
# This file contains:
#   - App configuration (session cookies, secret key, CSRF)
#   - Hardcoded user accounts and device state
#   - RBAC permission table and require_role() helper
#   - All routes: login, logout, dashboard, device control
#
# Security checks are gated on config.SECURITY_ENABLED so we can flip one
# variable in config.py to switch between the secure and broken demo states.

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_wtf.csrf import CSRFProtect
import config

# ─────────────────────────────────────────────────────────────────────────────
# APP SETUP
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Flask uses SECRET_KEY to cryptographically sign the session cookie.
# If an attacker doesn't know this key, they cannot forge or tamper with sessions.
app.config['SECRET_KEY'] = config.SECRET_KEY

# SECURITY MECHANISM: Secure session cookie flags
# HttpOnly=True  → JavaScript in the browser cannot read the cookie at all.
#                  This blocks an XSS attacker from stealing the session token
#                  via document.cookie even if they inject a script.
app.config['SESSION_COOKIE_HTTPONLY'] = True

# SameSite=Strict → The browser only sends this cookie when the request
#                   originates from this same site. A request triggered by a
#                   malicious third-party page (CSRF attack) will not carry
#                   the cookie, so the server won't see a valid session.
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# Secure=False for local HTTP development.
# In production set this to True so the cookie is only ever sent over HTTPS,
# preventing it from being intercepted on an unencrypted connection.
app.config['SESSION_COOKIE_SECURE'] = False

# SECURITY MECHANISM: CSRF token validation
# CSRFProtect generates a cryptographically random token per user session and
# requires it to be present in every POST request. Because a cross-site attacker
# cannot read the victim's token (same-origin policy), forged requests are
# rejected with HTTP 400 before any route logic runs.
# When SECURITY_ENABLED = False we call csrf.exempt() on the toggle route
# so forged requests are accepted — that is the attack demo.
csrf = CSRFProtect(app)


# ─────────────────────────────────────────────────────────────────────────────
# HARDCODED USER ACCOUNTS  (no database needed)
# ─────────────────────────────────────────────────────────────────────────────
# NOTE: Real apps hash passwords (bcrypt/argon2). Plaintext is acceptable here
#       because this demo focuses on RBAC and CSRF, not password storage.
USERS = {
    "owner": {"password": "owner123", "role": "owner"},
    "guest": {"password": "guest123", "role": "guest"},
    "child": {"password": "child123", "role": "child"},
}


# ─────────────────────────────────────────────────────────────────────────────
# DEVICE STATE  (in-memory — resets on server restart, no database needed)
# ─────────────────────────────────────────────────────────────────────────────
# 'active' semantics per device:
#   lock       → True = locked,   False = unlocked
#   cameras    → True = on,       False = off
#   thermostat → True = on,       False = off
#   lights     → True = on,       False = off
DEVICE_STATE = {
    "lock":       {"label": "Door Lock",  "active": True},
    "cameras":    {"label": "Cameras",    "active": True},
    "thermostat": {"label": "Thermostat", "active": False},
    "lights":     {"label": "Lights",     "active": False},
}


# ─────────────────────────────────────────────────────────────────────────────
# RBAC PERMISSION TABLE
# ─────────────────────────────────────────────────────────────────────────────
# Maps each device_id to the set of roles that are allowed to toggle it.
# This is the single source of truth for access control — both the server-side
# require_role() check and the dashboard UI read from this table.
#
# Permission summary (from CLAUDE.md):
#   Device      | owner | guest | child
#   ------------|-------|-------|------
#   lock        |  YES  |  NO   |  NO
#   cameras     |  YES  |  NO   |  NO
#   thermostat  |  YES  |  YES  |  NO
#   lights      |  YES  |  YES  |  NO
DEVICE_ROLES = {
    "lock":       {"owner"},
    "cameras":    {"owner"},
    "thermostat": {"owner", "guest"},
    "lights":     {"owner", "guest"},
}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def login_required():
    """Return a redirect to /login if no user is in the session, else None."""
    if 'username' not in session:
        return redirect(url_for('login'))
    return None


def require_role(device_id):
    """
    SECURITY MECHANISM: RBAC (Role-Based Access Control)

    Checks whether the currently logged-in user's role is in the allowed set
    for the given device. If not — and SECURITY_ENABLED is True — aborts with
    HTTP 403 Forbidden, which renders forbidden.html.

    When SECURITY_ENABLED = False this check is skipped entirely, so ANY
    logged-in user can control ANY device. That is the privilege-escalation
    attack demo: a 'guest' can unlock the door.

    Returns None if access is granted, never returns if access is denied
    (abort() raises an exception that Flask catches).
    """
    # SECURITY MECHANISM: RBAC check — disabled when SECURITY_ENABLED = False
    if config.SECURITY_ENABLED:
        role = session.get('role')
        allowed_roles = DEVICE_ROLES.get(device_id, set())
        if role not in allowed_roles:
            abort(403)  # → triggers the 403 error handler → forbidden.html


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE: / — redirect root to dashboard
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard'))


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE: /login  (GET = show form, POST = process credentials)
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Show the login form and authenticate the user on submit."""

    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = USERS.get(username)

        if user and user['password'] == password:
            # Store identity in the session cookie (signed with SECRET_KEY).
            session['username'] = username
            session['role'] = user['role']
            flash(f"Welcome, {username}! Logged in as {user['role']}.", 'success')
            return redirect(url_for('dashboard'))
        else:
            # Do NOT reveal which field was wrong — generic message only.
            flash('Invalid username or password.', 'error')

    return render_template('login.html')


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE: /logout
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/logout')
def logout():
    """Clear the session (log the user out) and redirect to login."""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE: /dashboard
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/dashboard')
def dashboard():
    """Show the smart home control panel with all device states."""

    redir = login_required()
    if redir:
        return redir

    return render_template(
        'dashboard.html',
        devices=DEVICE_STATE,
        device_roles=DEVICE_ROLES,   # passed so Jinja2 can hide forbidden buttons
        username=session['username'],
        role=session['role'],
    )


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE: /device/<device_id>/toggle  (POST only)
# ─────────────────────────────────────────────────────────────────────────────
# Handles the toggle button for ALL four devices.
# SECURITY NOTE: when SECURITY_ENABLED = False, csrf.exempt() is applied at
# startup (see below) so the CSRF check is skipped on this route.
@app.route('/device/<device_id>/toggle', methods=['GET', 'POST'])
def device_toggle(device_id):
    """Toggle a device on/off after checking login and RBAC.

    Accepts both GET and POST. The RBAC check runs on both methods, so a guest
    typing /device/lock/toggle in the browser still gets 403 Forbidden.
    """

    # Step 1 — must be logged in
    redir = login_required()
    if redir:
        return redir

    # Step 2 — reject unknown device IDs
    if device_id not in DEVICE_STATE:
        abort(404)

    # Step 3 — SECURITY MECHANISM: RBAC check
    # require_role() looks up session['role'] in DEVICE_ROLES[device_id].
    # If the role is not permitted AND SECURITY_ENABLED is True → HTTP 403.
    # If SECURITY_ENABLED is False → check is skipped, attack succeeds.
    require_role(device_id)

    # Step 4 — flip the device state (GET or POST)
    DEVICE_STATE[device_id]['active'] = not DEVICE_STATE[device_id]['active']
    label = DEVICE_STATE[device_id]['label']
    state = 'ON' if DEVICE_STATE[device_id]['active'] else 'OFF'
    flash(f"{label} is now {state}.", 'success')

    return redirect(url_for('dashboard'))


# ─────────────────────────────────────────────────────────────────────────────
# SECURITY MECHANISM: CSRF bypass when SECURITY_ENABLED = False
# ─────────────────────────────────────────────────────────────────────────────
# csrf.exempt() tells Flask-WTF to skip token validation for device_toggle.
# This must run AFTER the route is defined so the function object exists.
# When SECURITY_ENABLED = True  → this block is skipped, CSRF is enforced.
# When SECURITY_ENABLED = False → CSRF check is removed, forged requests
#   from attack.html will be accepted. That is the CSRF attack demo.
if not config.SECURITY_ENABLED:
    csrf.exempt(device_toggle)


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE: /attack  (GET only — serves the CSRF attack demo page)
# ─────────────────────────────────────────────────────────────────────────────
# This route serves attack.html, which simulates a malicious third-party website.
# The page contains a hidden form that auto-submits to /device/lock/toggle.
#
# With SECURITY_ENABLED = True  → the toggle route requires a valid CSRF token.
#   The forged form has no token, so Flask-WTF rejects it with HTTP 400.
#   The attack FAILS. The door lock is unchanged.
#
# With SECURITY_ENABLED = False → csrf.exempt(device_toggle) is active, so
#   the missing token is not checked. The forged POST goes through, the door
#   lock is toggled without the owner ever clicking anything.
#   The attack SUCCEEDS. This is the live demo moment.
#
# NOTE: Because attack.html is served from the same origin (localhost:5000),
#   the SameSite=Strict cookie flag does NOT block it — that flag only stops
#   requests originating from a *different* domain. In a real-world attack the
#   malicious page would be on attacker.com; here we keep everything on one
#   server for demo convenience. The CSRF token is the mechanism we are
#   demonstrating, and it is fully bypassed when SECURITY_ENABLED = False.
@app.route('/attack')
def attack():
    """Serve the simulated malicious CSRF attack page."""
    return render_template('attack.html')


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT PROCESSOR — inject config flag into every template automatically
# ─────────────────────────────────────────────────────────────────────────────
@app.context_processor
def inject_security_flag():
    """Make SECURITY_ENABLED available in all templates as config_security_enabled."""
    return {'config_security_enabled': config.SECURITY_ENABLED}


# ─────────────────────────────────────────────────────────────────────────────
# ERROR HANDLER: 403 Forbidden
# ─────────────────────────────────────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    """Render the custom 403 page when require_role() denies access."""
    return render_template('forbidden.html'), 403


# ─────────────────────────────────────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    # debug=True: auto-reloads on changes and shows detailed error pages.
    # NEVER use debug=True in production — it exposes an interactive Python shell.
    app.run(debug=True, use_reloader=False)
