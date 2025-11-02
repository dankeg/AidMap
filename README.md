# AidMap
Crowdsourced information about first-aid kits, AEDS, and other emergency supplies. 

## Configuration

Set the Mapbox access token before starting the server:

```bash
export MAPBOX_TOKEN="pk.your-token-here"
```

The Flask app will refuse to serve the main page if the token is missing.

### Moderator Credentials

Define moderator login credentials via environment variables before launching the app:

```bash
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="choose-a-strong-password"
```

- The username defaults to `admin` if `ADMIN_USERNAME` is omitted.
- When `ADMIN_PASSWORD` is not set the app generates a single-use random password at startup and logs it to stdout; make sure you capture it from the console and rotate it immediately.
- Updating `ADMIN_PASSWORD` and restarting the server will rotate the stored hash for the configured username.

### Two-Factor Authentication

- AidMap supports time-based one-time passwords (TOTP, Google Authenticator-compatible) for moderator logins.
- When the default `admin` account is auto-provisioned (no `ADMIN_PASSWORD` set) the server prints both the temporary password and a brand-new TOTP secret to stdout; enroll that secret in an authenticator app before attempting to log in.
- Moderators who log in with an environment-provided password can enable 2FA from the UI: open the moderator panel and click **Set Up Two-Factor Auth** to generate a unique secret and QR link.
- After enrollment, future logins require the six-digit code in addition to the password; losing the secret requires database access to clear the `totp_secret` column for that moderator.
- After deleting the SQLite database or bootstrapping a fresh environment, do the following:
	1. Start the Flask app and watch the server logs (`app.logger` writes to stderr). Capture the generated password and TOTP secret for the `admin` account.
	2. Add the secret to an authenticator app (Google Authenticator, 1Password, etc.) using either the raw code or the otpauth URL from the log output.
	3. Sign in to the moderator panel with the logged password plus the six-digit code from your authenticator.
	4. Immediately rotate the password (`export ADMIN_PASSWORD=...` and restart) once you confirm the TOTP token works.
	5. If you cannot access logs (e.g., managed hosting), set `ADMIN_BOOTSTRAP_PATH=/secure/location/bootstrap.txt` before launch; the app will write the same password and TOTP details to that file (chmod 600) when it auto-provisions the admin account.

## Database

- The SQLite database lives in `instance/medical_supplies.db` and is created automatically on first request.
- The schema is defined in `schema.sql`; update this file if you need to change tables.
- To reset the database, stop the server, delete `instance/medical_supplies.db`, and restart the app.

## Resource Types

- Edit `static/data/resource_types.json` to add or update emergency supply categories.
- Each entry supports `value` (stored in the database), `label` (shown in the UI), `markerColor`, `badgeBackground`, and `badgeColor`.
- Changes take effect on the next server restart; submissions are validated against this list.
