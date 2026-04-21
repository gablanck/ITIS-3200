# config.py — Application configuration and security toggle
#
# This file controls all major settings for the Smart Home Security Dashboard.
# The most important setting is SECURITY_ENABLED, which lets us demonstrate
# what happens when security mechanisms are turned off.

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY TOGGLE — THE MOST IMPORTANT SETTING IN THIS PROJECT
# ─────────────────────────────────────────────────────────────────────────────
# Set to True  → RBAC and CSRF protection are enforced (secure state)
# Set to False → All security checks are skipped (broken/attack demo state)
SECURITY_ENABLED = True

# ─────────────────────────────────────────────────────────────────────────────
# SECRET KEY — used by Flask to sign session cookies
# ─────────────────────────────────────────────────────────────────────────────
SECRET_KEY = 'dev-secret-key'
