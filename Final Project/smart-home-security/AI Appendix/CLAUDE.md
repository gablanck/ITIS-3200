# Smart Home Security Dashboard — Project Brief for Claude Code

## What This Project Is
A web-based Smart Home Security Dashboard built with Python and Flask.
It simulates a homeowner controlling IoT devices (door lock, cameras, thermostat, lights)
through a browser. The purpose is to demonstrate security mechanisms taught in a university
security course: RBAC, CSRF protection, and secure session cookies.

The project must show TWO states:
- SECURE state: all mechanisms enforced
- BROKEN state: mechanisms disabled, attacks succeed

This is a student academic project. Keep all code beginner-friendly, well-commented,
and easy to understand. Avoid unnecessary complexity.

---

## Tech Stack
- **Backend:** Python 3, Flask
- **Frontend:** HTML, CSS (plain, no frameworks needed), Jinja2 templates
- **Auth:** Flask sessions (server-side, no database needed)
- **CSRF:** Flask-WTF
- **Users:** Hardcoded Python dictionary (no database)

---

## Project Structure
```
smart-home-security/
├── app.py                  # Main Flask app
├── CLAUDE.md               # This file
├── README.md               # For GitHub / TAs
├── requirements.txt        # Python dependencies
├── config.py               # Security toggle + app config
├── templates/
│   ├── base.html           # Shared layout
│   ├── login.html          # Login page
│   ├── dashboard.html      # Main smart home control panel
│   ├── forbidden.html      # 403 error page
│   └── attack.html         # Simulated malicious CSRF attack page
└── static/
    └── style.css           # Basic styling
```

---

## Users & Roles (Hardcoded)
```python
USERS = {
    "owner": {"password": "owner123", "role": "owner"},
    "guest": {"password": "guest123", "role": "guest"},
    "child": {"password": "child123", "role": "child"},
}
```

## RBAC Permission Table
| Device Action         | Owner | Guest | Child |
|-----------------------|-------|-------|-------|
| View dashboard        | ✅    | ✅    | ✅    |
| Control lights        | ✅    | ✅    | ❌    |
| Control thermostat    | ✅    | ✅    | ❌    |
| View cameras          | ✅    | ❌    | ❌    |
| Lock / Unlock door    | ✅    | ❌    | ❌    |
| Manage users          | ✅    | ❌    | ❌    |

---

## Security Toggle (CRITICAL)
In `config.py` there must be a single variable:
```python
SECURITY_ENABLED = True  # Set to False to demonstrate attacks
```

When `SECURITY_ENABLED = False`:
- RBAC checks are skipped (any logged-in user can control any device)
- CSRF token validation is skipped (forged requests are accepted)

Every security check in the code must reference this variable with a clear comment like:
```python
# SECURITY MECHANISM: RBAC check — disabled when SECURITY_ENABLED = False
if config.SECURITY_ENABLED and session.get('role') != 'owner':
    abort(403)
```

This toggle is essential for the live attack demonstration

---

## The Three Security Mechanisms

### 1. RBAC (Primary Mechanism)
- Every POST route that controls a device must check the user's role
- Use a decorator or helper function called `require_role(role)` to keep it clean
- If the user's role is not permitted, return a 403 Forbidden response
- The dashboard UI should also hide buttons the user is not allowed to use
  (but the SERVER-SIDE check is what actually enforces security)

### 2. CSRF Tokens (Supporting Mechanism)
- Use Flask-WTF's CSRFProtect
- Every HTML form that controls a device must include `{{ csrf_token() }}`
- When SECURITY_ENABLED = False, CSRF validation must be bypassed
- Add a clear comment wherever this happens

### 3. Secure Session Cookies (Supporting Mechanism)
- Set in app config:
  - SESSION_COOKIE_HTTPONLY = True
  - SESSION_COOKIE_SAMESITE = 'Strict'
  - SESSION_COOKIE_SECURE = False (keep False for local dev, True in production)
- Add a comment explaining what each flag does

---

## Attack Demonstrations

### Attack 1: Privilege Escalation (RBAC removed)
- Login as "guest", then navigate directly to POST /device/lock/toggle
- With SECURITY_ENABLED = True → 403 Forbidden
- With SECURITY_ENABLED = False → door lock toggles successfully

### Attack 2: CSRF Attack (CSRF protection removed)
- `attack.html` is a standalone page simulating a malicious website
- It contains a hidden auto-submitting form targeting POST /device/lock/toggle
- With SECURITY_ENABLED = True → request rejected (invalid/missing CSRF token)
- With SECURITY_ENABLED = False → attack succeeds silently

---

## Implementation Phases

### ✅ Phase 1 — Setup (Do this first)
- [ ] Create all folders and files listed in Project Structure
- [ ] Create `requirements.txt` with: flask, flask-wtf
- [ ] Create `config.py` with SECURITY_ENABLED = True and SECRET_KEY
- [ ] Create a basic `app.py` that runs and shows "Hello World" at localhost:5000

### ✅ Phase 2 — Base App
- [ ] Build login/logout with Flask sessions
- [ ] Build dashboard showing all devices with their current state (on/off, locked/unlocked)
- [ ] Device state stored in a simple Python dictionary in memory (no database)
- [ ] Basic styling in style.css — clean and readable, not fancy

### ✅ Phase 3 — Security Mechanisms
- [ ] Implement RBAC with require_role() helper
- [ ] Apply RBAC to all device control routes
- [ ] Implement CSRF protection with Flask-WTF
- [ ] Add CSRF tokens to all forms
- [ ] Configure secure session cookie flags

### ✅ Phase 4 — Broken Version & Attack Demos
- [ ] Wire SECURITY_ENABLED toggle to all security checks
- [ ] Build attack.html CSRF demo page
- [ ] Test both attacks work when SECURITY_ENABLED = False
- [ ] Test both attacks are blocked when SECURITY_ENABLED = True

### ✅ Phase 5 — Polish & Deploy
- [ ] Write README.md 
- [ ] Add requirements.txt and verify pip install works cleanly

---

## Important Rules for Code Style
- Every security-relevant line must have a comment explaining WHY it is there
- Keep functions short and readable
- No external databases — keep state in Python dictionaries
- No JavaScript frameworks — plain HTML forms only
- All templates must extend base.html
- Show the logged-in username and role on every page

---

## How to Run Locally
```bash
pip install -r requirements.txt
python app.py
# Visit http://localhost:5000
```

---

## Current Status
> Update this section as you complete each phase so Claude Code always
> knows where the project stands.

- [x] Phase 1 — Setup
- [x] Phase 2 — Base App
- [x] Phase 3 — Security Mechanisms
- [x] Phase 4 — Broken Version & Attacks
- [x] Phase 5 — Deploy
