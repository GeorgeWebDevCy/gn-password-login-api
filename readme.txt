=== GN Password Login API ===
Contributors: georgenicolaou
Donate link: https://github.com/GeorgeWebDevCy/gn-password-login-api/
Tags: rest api, login, authentication, mobile, spa
Requires at least: 5.8
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Provides hardened REST endpoints for WordPress logins, user registration, and password resets with rate limiting, HTTPS enforcement, one-time tokens, and optional same-origin cookie login.

== Description ==

GN Password Login API exposes JSON endpoints (`/wp-json/gn/v1/*`) for logging in, registering, and initiating password resets. Login accepts a username or email address together with a password and optional `remember`, `mode`, and `redirect_to` fields, while registration validates new accounts and forgot-password leverages WordPress' built-in reset flow. It is designed for JavaScript single-page apps, native mobile applications, and other cross-origin clients that need to manage WordPress accounts without showing the core forms.

Key features:

* Requires HTTPS (unless explicitly allowed in development) and supports username or email based authentication.
* Rate limits login attempts to 5 per 15 minutes per IP and username and returns generic error messages to avoid user enumeration.
* Default `token` mode returns a one-time token and login URL with a 60 second TTL; tokens are tied to the requesting IP and user agent and are consumed at `/wp-login.php?action=gn_token_login&token=...&u=...`.
* Optional `cookie` mode sets the normal WordPress auth cookies immediately for same-origin usage.
* Registration endpoint validates usernames, enforces unique emails, and requires passwords of at least eight characters.
* Forgot-password endpoint triggers the standard WordPress reset email while keeping responses generic when the account is unknown.
* Settings page at **Settings ▸ GN Login API** lets administrators whitelist a single external origin for CORS while keeping same-origin access functional.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/gn-password-login-api` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. (Optional) Navigate to **Settings ▸ GN Login API** to define an allowed CORS origin for cross-origin clients.

== Frequently Asked Questions ==

= Can I call the endpoint over HTTP? =

No. The endpoint enforces HTTPS and returns an error when accessed insecurely unless the developer-only `ALLOW_DEV_HTTP` constant is toggled to `true` while `WP_DEBUG` is enabled.

= How do I use the token login flow? =

Send a POST request with `mode` omitted or set to `token`. On success you will receive `token_login_url`; opening that URL in a browser within 60 seconds will set the auth cookies (respecting the `remember` flag) and redirect to the sanitized `redirect_to` value.

= Can I set cookies directly from another domain? =

Only when using the `cookie` mode from the same origin as the WordPress site. Cross-origin clients should use the token flow to avoid CORS credential issues.

= How do registration and password reset work? =

Send a POST request to `/wp-json/gn/v1/register` with `username`, `email`, and `password` (plus optional profile fields) to create a new account. To start a reset email, POST `/wp-json/gn/v1/forgot-password` with the user's username or email; the response message is intentionally generic to prevent account enumeration.

== Changelog ==

= 1.1.0 =
* Added REST endpoints for user registration and initiating password resets.
* Documented new flows and strengthened password requirements for new accounts.

= 1.0.2 =
* Version bump for maintenance release.

= 1.0.1 =
* Initial public release of the hardened password login REST API.

== Upgrade Notice ==

= 1.1.0 =
Adds registration and password reset endpoints for complete account management from external clients.

= 1.0.2 =
Version bump for maintenance release.

= 1.0.1 =
This release introduces the secure REST login endpoint with rate limiting, token hand-offs, and admin-configurable CORS support.
