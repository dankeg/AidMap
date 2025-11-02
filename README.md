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

## Database

- The SQLite database lives in `instance/medical_supplies.db` and is created automatically on first request.
- The schema is defined in `schema.sql`; update this file if you need to change tables.
- To reset the database, stop the server, delete `instance/medical_supplies.db`, and restart the app.

## Resource Types

- Edit `static/data/resource_types.json` to add or update emergency supply categories.
- Each entry supports `value` (stored in the database), `label` (shown in the UI), `markerColor`, `badgeBackground`, and `badgeColor`.
- Changes take effect on the next server restart; submissions are validated against this list.
