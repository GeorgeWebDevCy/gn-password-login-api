# GN Password Login API

GN Password Login API is a WordPress plugin that exposes hardened REST endpoints for authenticating, registering, and resetting WordPress user passwords. It is designed for SPAs, mobile apps, and other cross-origin clients that need to manage accounts without sending users through the default WordPress forms.

## Features

- **REST login endpoint:** `POST /wp-json/gn/v1/login` accepts `username`, `password`, optional `remember`, `mode`, and `redirect_to` parameters.
- **Account registration endpoint:** `POST /wp-json/gn/v1/register` creates a new user with validated username, email, and password (optional profile fields supported).
- **Password reset initiation:** `POST /wp-json/gn/v1/forgot-password` triggers the core WordPress reset email without revealing whether the account exists.
- **HTTPS enforcement:** rejects requests made over insecure HTTP (unless `ALLOW_DEV_HTTP` is enabled for local development).
- **Rate limiting:** caps login attempts to 5 per 15-minute window per IP address and username.
- **Flexible identifiers:** allows users to authenticate using either their username or email address.
- **Two response modes:**
  - `mode: token` (default) returns a one-time login URL and token with a 60-second TTL for secure cross-origin hand-offs.
  - `mode: cookie` sets the WordPress auth cookies immediately for same-origin browser use.
- **Single-use token consumption:** `/wp-login.php?action=gn_token_login&token=...&u=...` consumes the token, verifies IP/UA, and redirects to a safe internal URL.
- **CORS control:** settings page under **Settings ▸ GN Login API** lets administrators whitelist a single external origin; same-origin requests work out-of-the-box.
- **Plugin self-updates:** integrates with the Plugin Update Checker library to pull updates from GitHub.

## Request and response examples

```http
POST /wp-json/gn/v1/login HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "username": "editor@example.com",
  "password": "correct horse battery staple",
  "remember": true,
  "mode": "token",
  "redirect_to": "https://example.com/app"
}
```

Successful token-mode response:

```json
{
  "success": true,
  "mode": "token",
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "token_expires_in": 60,
  "token_login_url": "https://example.com/wp-login.php?action=gn_token_login&token=...",
  "user": {
    "id": 123,
    "login": "editor",
    "email": "editor@example.com",
    "nicename": "editor",
    "display": "Editorial User"
  }
}
```

To complete the flow, open `token_login_url` in a browser/webview. The plugin validates the token, IP, and user agent, sets the auth cookies (honoring `remember`), and redirects to the sanitized `redirect_to` URL.

When `mode` is set to `cookie`, the endpoint immediately sets the auth cookies and returns a simplified success payload for same-origin usage.

### Registration

```http
POST /wp-json/gn/v1/register HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "aSecurePassword123",
  "first_name": "New",
  "last_name": "User"
}
```

Successful response:

```json
{
  "success": true,
  "message": "Account created successfully.",
  "user_id": 456
}
```

### Password reset

```http
POST /wp-json/gn/v1/forgot-password HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "login": "user@example.com"
}
```

Response (the message is identical even if the account does not exist to prevent enumeration):

```json
{
  "success": true,
  "message": "If the account exists, a password reset email has been sent."
}
```

## Configuration

1. Install and activate the plugin like any other WordPress plugin.
2. Visit **Settings ▸ GN Login API** to optionally configure an allowed CORS origin (e.g. `https://app.example.com`). Leave blank to restrict the endpoint to same-origin requests.
3. Ensure the site is served over HTTPS in production; the endpoint responds with an error when accessed over HTTP.

## Security considerations

- Requests are rate limited per IP and per username. Further protections (e.g. reCAPTCHA) can be layered on if desired.
- Registration validates usernames, enforces unique emails, and requires passwords of at least eight characters.
- Password reset responses remain generic when the account is unknown to avoid user enumeration.
- The plugin intentionally returns a generic error message for failed logins to avoid user enumeration.
- One-time tokens expire after 60 seconds and are restricted to the requesting IP/UA pair for additional safety.
- Redirect targets are sanitized to prevent external redirects.

## Development

The constant `ALLOW_DEV_HTTP` can be toggled to `true` inside `gn-password-login-api.php` to permit HTTP during local development while `WP_DEBUG` is enabled. Remember to set it back to `false` before deploying.

## License

Licensed under the GPL-2.0+ license.
