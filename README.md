# GN Password Login API

GN Password Login API is a WordPress plugin that exposes hardened REST endpoints for authenticating, registering, and resetting WordPress user passwords. It is designed for SPAs, mobile apps, and other cross-origin clients that need to manage accounts without sending users through the default WordPress forms.

## Features

- **REST login endpoint:** `POST /wp-json/gn/v1/login` accepts `username`, `password`, optional `remember`, `mode`, and `redirect_to` parameters.
- **Account registration endpoint:** `POST /wp-json/gn/v1/register` creates a new user with validated username, email, and password (optional profile fields supported).
- **Password reset initiation:** `POST /wp-json/gn/v1/forgot-password` triggers the core WordPress reset email without revealing whether the account exists.
- **Direct password reset:** `POST /wp-json/gn/v1/reset-password` lets you confirm the user through a custom verification code and immediately update the password without sending the default email.
- **Authenticated password change:** `POST /wp-json/gn/v1/change-password` lets logged-in users rotate their password after confirming the current one.
- **HTTPS enforcement:** rejects requests made over insecure HTTP (unless `ALLOW_DEV_HTTP` is enabled for local development).
- **Rate limiting:** caps login attempts to 5 per 15-minute window per IP address and username.
- **Flexible identifiers:** allows users to authenticate using either their username or email address.
- **Two response modes:**
  - `mode: token` (default) returns a one-time login URL and token with a one-year TTL for secure cross-origin hand-offs.
  - `mode: cookie` sets the WordPress auth cookies immediately for same-origin browser use.
- **Single-use token consumption:** `/wp-login.php?action=gn_token_login&token=...&u=...` consumes the token, optionally verifies the requesting IP/UA (when filters enable locking), and redirects to a safe internal URL.
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
  "token_expires_in": 31536000,
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

To complete the flow, open `token_login_url` in a browser/webview. The plugin validates the token, optionally checks the IP and user agent when locking is enabled, sets the auth cookies (honoring `remember`), and redirects to the sanitized `redirect_to` URL.

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

### Password reset (email flow)

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

### Password reset (custom verification flow)

This endpoint is intended for cases where you verify the user through an out-of-band channel (SMS, help desk workflow, in-person, etc.) and want to avoid sending the default WordPress email. Generate a verification code using the helper and deliver it via your preferred channel, then call the endpoint with that code.

1. Generate and deliver a one-time code:

```php
$code = GN_Password_Login_API::issue_reset_verification_code($user_id, 900); // 15 minute TTL
// Send $code through your trusted channel.
```

2. From your application, reset the password:

```http
POST /wp-json/gn/v1/reset-password HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "login": "user@example.com",
  "verification_code": "the-code-you-issued",
  "new_password": "a brand new password",
  "confirm_password": "a brand new password"
}
```

Successful response:

```json
{
  "success": true,
  "message": "Password updated successfully."
}
```

If you prefer your own verification logic, hook into the `gn_password_api_validate_reset_verification` filter. Return `true` to allow the reset, `false` to reject it, or a `WP_Error` for a custom error response.

### Password change (authenticated users)

```http
POST /wp-json/gn/v1/change-password HTTP/1.1
Host: example.com
Content-Type: application/json
Cookie: wordpress_logged_in=...

{
  "current_password": "existing password",
  "new_password": "a new, stronger password",
  "confirm_password": "a new, stronger password"
}
```

Successful response:

```json
{
  "success": true,
  "message": "Password updated successfully."
}
```

The endpoint requires the caller to already be authenticated (via cookies or another REST auth method), enforces the same minimum length as registration, re-validates the current password, and refreshes the session after the password change.

## Configuration

1. Install and activate the plugin like any other WordPress plugin.
2. Visit **Settings ▸ GN Login API** to optionally configure an allowed CORS origin (e.g. `https://app.example.com`). Leave blank to restrict the endpoint to same-origin requests.
3. Ensure the site is served over HTTPS in production; the endpoint responds with an error when accessed over HTTP.

## Security considerations

- Requests are rate limited per IP and per username. Further protections (e.g. reCAPTCHA) can be layered on if desired.
- Registration validates usernames, enforces unique emails, and requires passwords of at least eight characters.
- Password reset responses remain generic when the account is unknown to avoid user enumeration.
- The plugin intentionally returns a generic error message for failed logins to avoid user enumeration.
- One-time tokens expire after one year and can optionally be restricted to the requesting IP and/or user agent through filters.
- Redirect targets are sanitized to prevent external redirects.

## Hooks

- `gn_password_api_lock_token_to_ip`: return `true` to tie newly issued token URLs to the requesting IP address. Defaults to `false` to support mobile/native hand-offs where IPs may change between requests.
- `gn_password_api_lock_token_to_user_agent`: return `true` to require that the consuming browser/user agent matches the one that requested the token. Defaults to `false` to avoid mismatches between native apps and in-app browsers.
- `gn_password_api_validate_token_payload`: run final validation before the auth cookies are issued. Return `false` or a `WP_Error` to reject the token.

## Development

The constant `ALLOW_DEV_HTTP` can be toggled to `true` inside `gn-password-login-api.php` to permit HTTP during local development while `WP_DEBUG` is enabled. Remember to set it back to `false` before deploying.

## License

Licensed under the GPL-2.0+ license.
