#!/usr/bin/env python3
"""Zoho Mail alias manager — list and add email aliases via the Zoho Mail API.

Usage:
    python zoho_aliases.py auth               # First-time OAuth setup
    python zoho_aliases.py list               # List aliases (uses ZOHO_ACCOUNT_ID)
    python zoho_aliases.py list --account-id <id>
    python zoho_aliases.py add alias@domain.com
    python zoho_aliases.py add alias@domain.com --org-id <id> --user-id <id>
"""

import argparse
import json
import os
import sys
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Config (all overridable via CLI flags)
# ---------------------------------------------------------------------------
CLIENT_ID = os.getenv("ZOHO_CLIENT_ID")
CLIENT_SECRET = os.getenv("ZOHO_CLIENT_SECRET")
REDIRECT_URI = os.getenv("ZOHO_REDIRECT_URI", "http://localhost:8080")
REFRESH_TOKEN = os.getenv("ZOHO_REFRESH_TOKEN")
ORG_ID = os.getenv("ZOHO_ORG_ID")
ACCOUNT_ID = os.getenv("ZOHO_ACCOUNT_ID")
BASE_URL = os.getenv("ZOHO_BASE_URL", "https://mail.zoho.com").rstrip("/")
ACCOUNTS_URL = os.getenv("ZOHO_ACCOUNTS_URL", "https://accounts.zoho.com").rstrip("/")

TOKEN_FILE = ".tokens.json"
SCOPES = "ZohoMail.accounts.READ,ZohoMail.organization.accounts.ALL"


# ---------------------------------------------------------------------------
# OAuth helpers
# ---------------------------------------------------------------------------

def _save_tokens(tokens: dict) -> None:
    with open(TOKEN_FILE, "w") as f:
        json.dump(tokens, f, indent=2)


def _load_refresh_token() -> str | None:
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as f:
            data = json.load(f)
        token = data.get("refresh_token")
        if token:
            return token
    return REFRESH_TOKEN


def _refresh_access_token(refresh_token: str) -> str:
    resp = requests.post(
        f"{ACCOUNTS_URL}/oauth/v2/token",
        params={
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "refresh_token",
        },
        timeout=15,
    )
    if not resp.ok:
        sys.exit(f"Token refresh error {resp.status_code}: {resp.text}")
    data = resp.json()
    if "access_token" not in data:
        sys.exit(f"Token refresh failed: {data}")
    # api_domain tells us the correct regional API base (e.g. zohoapis.eu → mail.zoho.eu)
    if "api_domain" in data:
        api_domain = data["api_domain"]  # e.g. https://www.zohoapis.eu
        region = api_domain.replace("https://www.zohoapis.", "").replace("https://zohoapis.", "")
        derived_base = f"https://mail.zoho.{region}"
        _save_tokens({"refresh_token": refresh_token, "access_token": data["access_token"], "base_url": derived_base})
    else:
        _save_tokens({"refresh_token": refresh_token, "access_token": data["access_token"]})
    return data["access_token"]


def run_oauth_flow() -> str:
    """Interactive OAuth authorization code flow. Opens the browser and
    captures the redirect on a local HTTP server. Returns a valid access token."""

    if not CLIENT_ID or not CLIENT_SECRET:
        sys.exit(
            "ZOHO_CLIENT_ID and ZOHO_CLIENT_SECRET must be set in .env before running auth."
        )

    auth_params = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPES,
            "access_type": "offline",
        }
    )
    auth_url = f"{ACCOUNTS_URL}/oauth/v2/auth?{auth_params}"

    print(f"\nOpening browser for Zoho authorization …\n\nIf the browser does not open, visit:\n{auth_url}\n")
    webbrowser.open(auth_url)

    # Spin up a one-shot local server to capture the authorization code.
    code_holder: dict[str, str | None] = {"code": None}

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            code_holder["code"] = (params.get("code") or [None])[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Authorization successful! You may close this tab.")

        def log_message(self, *_):
            pass  # suppress request logs

    parsed = urllib.parse.urlparse(REDIRECT_URI)
    host = parsed.hostname or "localhost"
    port = parsed.port or 8080

    class _Server(HTTPServer):
        allow_reuse_address = True

    server = _Server((host, port), _Handler)
    print(f"Waiting for OAuth callback on {REDIRECT_URI} …")
    server.handle_request()
    server.server_close()

    code = code_holder["code"]
    if not code:
        sys.exit("No authorization code received. Aborting.")

    # Exchange code for tokens.
    resp = requests.post(
        f"{ACCOUNTS_URL}/oauth/v2/token",
        params={
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
        },
        timeout=15,
    )
    resp.raise_for_status()
    tokens = resp.json()

    if "access_token" not in tokens:
        sys.exit(f"Token exchange failed: {tokens}")

    _save_tokens(tokens)

    print(f"\nTokens saved to {TOKEN_FILE} (gitignored).")
    if tokens.get("refresh_token"):
        print(
            "\nTo skip re-auth in future sessions, add this line to your .env:\n"
            f"  ZOHO_REFRESH_TOKEN={tokens['refresh_token']}\n"
        )

    return tokens["access_token"]


def get_access_token() -> str:
    """Return a valid access token, running the OAuth flow if necessary."""
    refresh_token = _load_refresh_token()
    if refresh_token:
        return _refresh_access_token(refresh_token)
    return run_oauth_flow()


def _auth_headers(access_token: str) -> dict:
    return {
        "Authorization": f"Zoho-oauthtoken {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _base_url() -> str:
    """Return the correct regional mail base URL, derived from the token file if available."""
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as f:
            data = json.load(f)
        if "base_url" in data:
            return data["base_url"].rstrip("/")
    return BASE_URL


# ---------------------------------------------------------------------------
# Core commands
# ---------------------------------------------------------------------------

def list_aliases(account_id: str | None = None) -> None:
    """Print all email aliases. Uses GET /api/accounts which returns aliases directly."""
    token = get_access_token()
    resp = requests.get(f"{_base_url()}/api/accounts", headers=_auth_headers(token), timeout=15)
    if not resp.ok:
        sys.exit(f"API error {resp.status_code}: {resp.text}")

    accounts = resp.json().get("data", [])

    # Filter to a specific account if requested, otherwise show all
    target_id = account_id or ACCOUNT_ID
    if target_id:
        accounts = [a for a in accounts if str(a.get("zuid")) == str(target_id) or a.get("accountId") == str(target_id) or a.get("primaryEmailAddress") == target_id or a.get("mailboxAddress") == target_id]
        if not accounts:
            sys.exit(f"No account found matching ID {target_id}.")

    for account in accounts:
        primary = account.get("primaryEmailAddress", account.get("accountId"))
        email_addresses = account.get("emailAddress", [])
        aliases = [e for e in email_addresses if e.get("isAlias")]

        if not aliases:
            print(f"No aliases found for {primary}.")
            continue

        print(f"\nAliases for {primary}:")
        for alias in aliases:
            mail_id = alias.get("mailId", "—")
            confirmed = "confirmed" if alias.get("isConfirmed") else "pending confirmation"
            print(f"  {mail_id}  [{confirmed}]")
    print()


def _resolve_zuid(identifier: str, token: str) -> int:
    """Resolve a ZUID from a numeric ID or an email address."""
    if identifier.lstrip("-").isdigit():
        return int(identifier)
    # Look up by email in the accounts list
    resp = requests.get(f"{_base_url()}/api/accounts", headers=_auth_headers(token), timeout=15)
    if not resp.ok:
        sys.exit(f"API error {resp.status_code}: {resp.text}")
    for account in resp.json().get("data", []):
        if account.get("primaryEmailAddress") == identifier or account.get("mailboxAddress") == identifier:
            return int(account["zuid"])
    sys.exit(f"No account found matching '{identifier}'.")


def add_alias(alias_email: str, org_id: str | None = None, user_id: str | None = None) -> None:
    """Add a new email alias to a Zoho Mail account."""
    zoid = org_id or ORG_ID
    raw_uid = user_id or ACCOUNT_ID

    if not zoid:
        sys.exit("Org ID is required. Pass --org-id or set ZOHO_ORG_ID in .env.")
    if not raw_uid:
        sys.exit("User ID is required. Pass --user-id or set ZOHO_ACCOUNT_ID in .env.")

    token = get_access_token()
    zuid = _resolve_zuid(raw_uid, token)
    url = f"{_base_url()}/api/organization/{zoid}/accounts/{zuid}"
    body = {
        "mode": "addEmailAlias",
        "emailAlias": [alias_email],
        "zuid": zuid,
    }

    resp = requests.put(url, headers=_auth_headers(token), json=body, timeout=15)
    resp.raise_for_status()
    data = resp.json()

    status = data.get("status", {})
    if status.get("code") == 200:
        print(f"\nAlias added successfully: {alias_email}")
    else:
        print(f"\nUnexpected response:\n{json.dumps(data, indent=2)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Manage Zoho Mail email aliases.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # auth
    sub.add_parser("auth", help="Run the OAuth flow and save tokens.")

    # list
    list_p = sub.add_parser("list", help="List all aliases for an account.")
    list_p.add_argument(
        "--account-id",
        metavar="ID",
        help="Zoho account ID (ZUID). Overrides ZOHO_ACCOUNT_ID from .env.",
    )

    # add
    add_p = sub.add_parser("add", help="Add a new alias to an account.")
    add_p.add_argument("alias", metavar="ALIAS_EMAIL", help="Alias email address to add.")
    add_p.add_argument(
        "--org-id",
        metavar="ID",
        help="Zoho organization ID. Overrides ZOHO_ORG_ID from .env.",
    )
    add_p.add_argument(
        "--user-id",
        metavar="ID",
        help="Zoho user ID (ZUID). Overrides ZOHO_ACCOUNT_ID from .env.",
    )

    args = parser.parse_args()

    if args.command == "auth":
        run_oauth_flow()
    elif args.command == "list":
        list_aliases(account_id=args.account_id)
    elif args.command == "add":
        add_alias(args.alias, org_id=args.org_id, user_id=args.user_id)


if __name__ == "__main__":
    main()
