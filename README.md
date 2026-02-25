# zoho

A command-line tool to manage Zoho Mail email aliases.

## How it works

The tool uses the [Zoho Mail API](https://www.zoho.com/mail/help/api/) with OAuth 2.0. On first run it opens a browser for authorization, then automatically discovers and saves your account details (ZUID, Org ID, regional API URL) to `~/.config/zoho-mail/config.json`. Subsequent commands use the saved refresh token silently — no browser needed.

Your Client ID and Client Secret are the only values you manage manually, kept in a `.env` file.

---

## Setup

### 1. Register a Zoho API app

1. Go to [api-console.zoho.com](https://api-console.zoho.com/)
2. Click **Add Client** → **Server-based Applications**
3. Fill in:
   - **Homepage URL**: `http://localhost`
   - **JavaScript Domain**: `http://localhost`
   - **Authorized Redirect URIs**: `http://localhost:9090`
4. Click **Create** — copy the **Client ID** and **Client Secret**

### 2. Create your `.env` file

```bash
cp .env.example .env
```

Edit `.env`:

```env
ZOHO_CLIENT_ID=your_client_id_here
ZOHO_CLIENT_SECRET=your_client_secret_here
```

### 3. Install dependencies

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Authenticate

```bash
python zoho.py auth
```

This will:
1. Ask you to select your Zoho region (EU, US, India, etc.)
2. Open your browser for OAuth consent
3. Auto-discover your account details (ZUID, Org ID, mail API URL)
4. Save everything to `~/.config/zoho-mail/config.json`

You only need to run `auth` once. If you run `list` or `add` without having authenticated, the auth flow starts automatically.

---

## Usage

```bash
# List all aliases for your account
python zoho.py list

# List aliases for a specific account (if you have multiple)
python zoho.py list mail@yourdomain.com

# Add a new alias
python zoho.py add newalias@yourdomain.com

# Add a new alias to a specific account
python zoho.py add newalias@yourdomain.com -a mail@yourdomain.com
```

---

## Config files

| File | Purpose |
|---|---|
| `.env` | Client ID + Client Secret (you manage this, never commit) |
| `~/.config/zoho-mail/config.json` | Tokens + account details (auto-managed by the tool) |

---

## Install via Homebrew (personal tap)

```bash
brew tap costajor/tap https://github.com/costajor/homebrew-tap
brew install costajor/tap/zoho
```

Once installed, the tool is available globally as `zoho` — no need to prefix with `python`.

To publish a new version:

1. Tag the release: `git tag v1.0.0 && git push --tags`
2. Get the tarball sha256:
   ```bash
   curl -sL https://github.com/costajor/zoho-mail/archive/refs/tags/v1.0.0.tar.gz | shasum -a 256
   ```
3. Update `sha256` in `Formula/zoho.rb` and push to your tap repo

During development you can install directly from the `main` branch:

```bash
brew install --HEAD costajor/tap/zoho
```

---

## Re-authenticating

If your refresh token expires or you switch accounts, just run:

```bash
zoho auth
```

It will re-use the credentials from `.env` and walk through the OAuth flow again.
