# Smart Home Security Dashboard

A browser-based Smart Home Security Dashboard built with Python and Flask for ITIS 3200. It simulates a homeowner controlling IoT devices (door lock, cameras, thermostat, and lights) through a web interface, and demonstrates three core security mechanisms — RBAC, CSRF protection, and secure session cookies — by letting you toggle all protections off with a single config flag so you can watch the attacks succeed live.

---

## Security Mechanisms

| Mechanism | What it does |
|---|---|
| **RBAC** (Role-Based Access Control) | Restricts which device actions each user role (owner / guest / child) is allowed to perform; forbidden actions return HTTP 403. |
| **CSRF Protection** | Flask-WTF generates a secret per-session token that must be present in every POST form; forged requests from other pages lack the token and are rejected with HTTP 400. |
| **Secure Session Cookies** | Three cookie flags protect the session: `HttpOnly` blocks JavaScript from reading it, `SameSite=Strict` stops it being sent on cross-site requests, and `Secure` (enabled in production) ensures it only travels over HTTPS. |

---

## Setup — Run Locally

### 1. Clone the repository
```bash
git clone <your-repo-url>
cd smart-home-security
```

### 2. (Optional) Create a virtual environment
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the app
```bash
python app.py
```

### 5. Open in your browser
```
http://localhost:5000
```

---

## Test Accounts

| Username | Password | Role | What they can control |
|---|---|---|---|
| `owner` | `owner123` | Owner | Everything — lock, cameras, thermostat, lights |
| `guest` | `guest123` | Guest | Thermostat and lights only |
| `child` | `child123` | Child | View dashboard only — no device controls |

Log in with any account at `http://localhost:5000/login`.

---

## Toggling Security On and Off

Open `config.py` and change the single toggle at the top:

```python
# config.py
SECURITY_ENABLED = True   # ← secure state: RBAC + CSRF enforced
SECURITY_ENABLED = False  # ← broken state: all protections disabled
```

**Restart the server** after changing the value — Flask loads `config.py` at startup.

| `SECURITY_ENABLED` | RBAC | CSRF | Effect |
|---|---|---|---|
| `True` | Enforced | Enforced | Guest/child blocked from forbidden devices; forged forms rejected |
| `False` | Skipped | Skipped | Any logged-in user controls any device; forged forms accepted |

The security status banner at the bottom of the dashboard always shows the current state.

---

## Attack Demonstrations

### Attack 1 — Privilege Escalation (RBAC disabled)

This shows what happens when role checks are removed and a low-privilege user
gains access to a device they should never touch.

1. In `config.py` set `SECURITY_ENABLED = False` and restart the server.
2. Log in as **guest** (`guest / guest123`).
3. On the dashboard, click **Lock** or **Unlock** on the Door Lock card.
4. The door lock toggles — even though guests are never supposed to control it.
5. **With `SECURITY_ENABLED = True`**: the same click returns **403 Forbidden**.

### Attack 2 — CSRF (Cross-Site Request Forgery)

This shows how a malicious page can silently perform an action on behalf of a
logged-in user without their knowledge or consent.

1. In `config.py` set `SECURITY_ENABLED = False` and restart the server.
2. Log in as **owner** (`owner / owner123`).
3. Note the current state of the Door Lock on the dashboard (e.g. LOCKED).
4. In the **same browser**, open a new tab and go to `http://localhost:5000/attack`.
5. The fake "prize website" loads. Wait 3 seconds — no clicking required.
6. The page will show an explanation panel: the attack has fired.
7. Click **"Go to Dashboard to confirm lock changed"** — the lock is now in the
   opposite state even though you never clicked anything on the dashboard.
8. **With `SECURITY_ENABLED = True`**: repeat steps 2–6. The attack fires but
   Flask-WTF rejects the forged POST (no CSRF token) with **400 Bad Request**.
   The lock state is unchanged.

---

## Project Structure

```
smart-home-security/
│
├── app.py              # Main Flask app: routes, RBAC, session management,
│                       # CSRF wiring, device state dictionary
│
├── config.py           # Single SECURITY_ENABLED toggle + SECRET_KEY
│
├── requirements.txt    # Python dependencies (flask, flask-wtf, gunicorn)
│
├── CLAUDE.md           # Project brief and instructions for Claude Code
│
├── templates/
│   ├── base.html       # Shared page layout: header with logged-in user,
│   │                   # flash messages, footer — all pages extend this
│   ├── login.html      # Login form (username + password + CSRF token)
│   ├── dashboard.html  # Device control panel; buttons hidden/shown by role
│   ├── forbidden.html  # 403 error page shown when an RBAC check fails
│   └── attack.html     # Standalone fake "prize" page — CSRF attack demo;
│                       # does NOT extend base.html (simulates a foreign site)
│
└── static/
    └── style.css       # Plain CSS styling — no frameworks
```

---

## How Security Checks Are Structured in the Code

Every security-relevant line in `app.py` is prefixed with a comment of the form:

```python
# SECURITY MECHANISM: <name> — disabled when SECURITY_ENABLED = False
if config.SECURITY_ENABLED:
    ...
```

This makes every check easy to find with a text search and easy to understand
during a live code walkthrough.
