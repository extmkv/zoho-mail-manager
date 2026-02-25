#!/usr/bin/env python3
"""zoho — Manage Zoho Mail email aliases.

Usage:
    zoho auth              Set up authentication (run once)
    zoho list              List aliases for all accounts
    zoho list EMAIL        List aliases for a specific account
    zoho add ALIAS         Add alias to the default account
    zoho add ALIAS -a EMAIL  Add alias to a specific account
"""

import argparse
import json
import os
import sys
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

CONFIG_DIR = Path.home() / ".config" / "zoho-mail"
CONFIG_FILE = CONFIG_DIR / "config.json"
REDIRECT_URI = "http://localhost:9090"
SCOPES = "ZohoMail.accounts.READ,ZohoMail.organization.accounts.ALL"

REGIONS = [
    ("US / Global",  "https://accounts.zoho.com"),
    ("Europe",       "https://accounts.zoho.eu"),
    ("India",        "https://accounts.zoho.in"),
    ("Australia",    "https://accounts.zoho.com.au"),
    ("Japan",        "https://accounts.zoho.jp"),
    ("Canada",       "https://accounts.zohocloud.ca"),
]


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def load_config() -> dict:
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def save_config(cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def _require_config() -> dict:
    cfg = load_config()
    if not cfg.get("refresh_token"):
        print("No configuration found. Starting setup…\n")
        cmd_auth(None)
        cfg = load_config()
    return cfg


# ---------------------------------------------------------------------------
# API / token helpers
# ---------------------------------------------------------------------------

def _api_headers(token: str) -> dict:
    return {
        "Authorization": f"Zoho-oauthtoken {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _get_access_token(cfg: dict) -> str:
    resp = requests.post(
        f"{cfg['accounts_url']}/oauth/v2/token",
        params={
            "refresh_token": cfg["refresh_token"],
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "grant_type": "refresh_token",
        },
        timeout=15,
    )
    if not resp.ok:
        sys.exit(f"Token refresh failed: {resp.text}")
    data = resp.json()
    if "access_token" not in data:
        sys.exit(f"Token refresh failed: {data}")

    # Keep base_url in sync with what Zoho reports
    if "api_domain" in data:
        region = (
            data["api_domain"]
            .replace("https://www.zohoapis.", "")
            .replace("https://zohoapis.", "")
        )
        cfg["base_url"] = f"https://mail.zoho.{region}"
        save_config(cfg)

    return data["access_token"]


def _fetch_raw_accounts(cfg: dict, token: str) -> list:
    resp = requests.get(
        f"{cfg['base_url']}/api/accounts",
        headers=_api_headers(token),
        timeout=15,
    )
    if not resp.ok:
        sys.exit(f"Failed to fetch accounts: {resp.text}")
    return resp.json().get("data", [])


def _save_accounts(cfg: dict, raw: list) -> list:
    """Parse raw Zoho account list and persist to config."""
    accounts = []
    for a in raw:
        policy = a.get("policyId", {})
        org_id = policy.get("zoid") if isinstance(policy, dict) else None
        accounts.append({
            "email":      a.get("primaryEmailAddress"),
            "zuid":       a.get("zuid"),
            "account_id": a.get("accountId"),
            "org_id":     org_id,
            "is_default": a.get("isDefaultAccount", False),
        })
    cfg["accounts"] = accounts
    save_config(cfg)
    return accounts


def _resolve_account(cfg: dict, identifier: str | None) -> dict:
    accounts = cfg.get("accounts", [])
    if not accounts:
        sys.exit("No accounts saved. Re-run 'zoho auth'.")
    if not identifier:
        return next((a for a in accounts if a.get("is_default")), accounts[0])
    for a in accounts:
        if a.get("email") == identifier or str(a.get("zuid")) == identifier:
            return a
    sys.exit(f"No account found matching '{identifier}'.")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_auth(_args) -> None:
    cfg = load_config()

    print("Zoho Mail Setup")
    print("─" * 40)

    # Credentials come from .env
    client_id = os.getenv("ZOHO_CLIENT_ID")
    client_secret = os.getenv("ZOHO_CLIENT_SECRET")

    if not client_id or not client_secret:
        sys.exit(
            "ZOHO_CLIENT_ID and ZOHO_CLIENT_SECRET must be set in your .env file.\n"
            "Register your app at: https://api-console.zoho.com/\n"
            f"Set the redirect URI to: {REDIRECT_URI}"
        )

    cfg["client_id"] = client_id
    cfg["client_secret"] = client_secret

    # Region selection
    current_url = cfg.get("accounts_url", "")
    print("\nSelect your Zoho region:")
    for i, (label, url) in enumerate(REGIONS, 1):
        marker = " ← current" if url == current_url else ""
        print(f"  {i}. {label}{marker}")

    while True:
        choice = input(f"\nRegion [1-{len(REGIONS)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(REGIONS):
            label, cfg["accounts_url"] = REGIONS[int(choice) - 1]
            print(f"Selected: {label}")
            break
        print("Invalid choice, try again.")

    save_config(cfg)

    # OAuth browser flow
    auth_params = urllib.parse.urlencode({
        "client_id":     cfg["client_id"],
        "response_type": "code",
        "redirect_uri":  REDIRECT_URI,
        "scope":         SCOPES,
        "access_type":   "offline",
        "prompt":        "consent",
    })
    auth_url = f"{cfg['accounts_url']}/oauth/v2/auth?{auth_params}"
    print(f"\nOpening browser for authorization…\nIf it doesn't open, visit:\n{auth_url}\n")
    webbrowser.open(auth_url)

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
            pass

    class _Server(HTTPServer):
        allow_reuse_address = True

    parsed = urllib.parse.urlparse(REDIRECT_URI)
    server = _Server((parsed.hostname, parsed.port), _Handler)
    print("Waiting for OAuth callback…")
    server.handle_request()
    server.server_close()

    code = code_holder["code"]
    if not code:
        sys.exit("No authorization code received.")

    resp = requests.post(
        f"{cfg['accounts_url']}/oauth/v2/token",
        params={
            "code":          code,
            "client_id":     cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "redirect_uri":  REDIRECT_URI,
            "grant_type":    "authorization_code",
        },
        timeout=15,
    )
    if not resp.ok:
        sys.exit(f"Token exchange failed: {resp.text}")
    tokens = resp.json()
    if "access_token" not in tokens:
        sys.exit(f"Token exchange failed: {tokens}")

    # Zoho may omit refresh_token if one already exists for this app;
    # keep the previously saved one in that case.
    if "refresh_token" in tokens:
        cfg["refresh_token"] = tokens["refresh_token"]
    elif not cfg.get("refresh_token"):
        sys.exit("No refresh token received and none previously saved. "
                 "Revoke the app's access in your Zoho account and try again.")

    # Derive the correct regional mail API URL from the token response
    if "api_domain" in tokens:
        region = (
            tokens["api_domain"]
            .replace("https://www.zohoapis.", "")
            .replace("https://zohoapis.", "")
        )
        cfg["base_url"] = f"https://mail.zoho.{region}"
    else:
        cfg["base_url"] = "https://mail.zoho.com"

    save_config(cfg)

    # Auto-discover account details
    print("\nFetching account details…")
    raw = _fetch_raw_accounts(cfg, tokens["access_token"])
    accounts = _save_accounts(cfg, raw)

    print(f"\nSetup complete. Config saved to {CONFIG_FILE}")
    print(f"Mail API: {cfg['base_url']}\n")
    for a in accounts:
        default = " (default)" if a.get("is_default") else ""
        print(f"  {a['email']}{default}")
        print(f"    ZUID: {a['zuid']}  |  Org ID: {a['org_id']}")


def cmd_list(args) -> None:
    cfg = _require_config()
    token = _get_access_token(cfg)
    raw_accounts = _fetch_raw_accounts(cfg, token)

    target = getattr(args, "account", None)
    if target:
        raw_accounts = [
            a for a in raw_accounts
            if a.get("primaryEmailAddress") == target
            or str(a.get("zuid")) == target
        ]
        if not raw_accounts:
            sys.exit(f"No account found matching '{target}'.")

    found_any = False
    for account in raw_accounts:
        primary = account.get("primaryEmailAddress")
        aliases = [e for e in account.get("emailAddress", []) if e.get("isAlias")]
        if not aliases:
            print(f"No aliases for {primary}.")
            continue
        found_any = True
        print(f"\nAliases for {primary}:")
        for alias in aliases:
            status = "confirmed" if alias.get("isConfirmed") else "pending"
            print(f"  {alias['mailId']}  [{status}]")

    if found_any:
        print()


def cmd_add(args) -> None:
    cfg = _require_config()
    token = _get_access_token(cfg)
    account = _resolve_account(cfg, getattr(args, "account", None))

    org_id = account.get("org_id")
    zuid = account.get("zuid")

    if not org_id:
        sys.exit("Missing org ID — re-run 'zoho auth' to refresh account details.")

    url = f"{cfg['base_url']}/api/organization/{org_id}/accounts/{zuid}"
    body = {
        "mode":       "addEmailAlias",
        "emailAlias": [args.alias],
        "zuid":       int(zuid),
    }

    resp = requests.put(url, headers=_api_headers(token), json=body, timeout=15)
    if not resp.ok:
        sys.exit(f"API error {resp.status_code}: {resp.text}")

    data = resp.json()
    if data.get("status", {}).get("code") == 200:
        print(f"Alias added: {args.alias} → {account['email']}")
    else:
        print(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="zoho",
        description="Manage Zoho Mail email aliases.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("auth", help="Set up authentication and auto-detect account details.")

    list_p = sub.add_parser("list", help="List all aliases.")
    list_p.add_argument("account", nargs="?", metavar="EMAIL",
                        help="Filter to a specific account email or ZUID.")

    add_p = sub.add_parser("add", help="Add a new alias.")
    add_p.add_argument("alias", metavar="ALIAS_EMAIL", help="Alias address to add.")
    add_p.add_argument("-a", "--account", metavar="EMAIL",
                       help="Target account email or ZUID (default: primary account).")

    args = parser.parse_args()

    if args.command == "auth":
        cmd_auth(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "add":
        cmd_add(args)


if __name__ == "__main__":
    main()
