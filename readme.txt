=== GN Password Login API ===
Contributors: georgenicolaou
Donate link: https://github.com/GeorgeWebDevCy/gn-password-login-api/
Tags: rest api, login, authentication, mobile, spa
Requires at least: 5.8
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 1.3.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Provides hardened REST endpoints for WordPress logins, user registration, and password resets with rate limiting, HTTPS enforcement, one-time tokens, and optional same-origin cookie login.

== Description ==

GN Password Login API exposes JSON endpoints (`/wp-json/gn/v1/*`) for logging in, registering, and initiating password resets. Login accepts a username or email address together with a password and optional `remember`, `mode`, and `redirect_to` fields, while registration validates new accounts and forgot-password leverages WordPress' built-in reset flow. It is designed for JavaScript single-page apps, native mobile applications, and other cross-origin clients that need to manage WordPress accounts without showing the core forms.

Key features:

* Requires HTTPS (unless explicitly allowed in development) and supports username or email based authentication.
* Rate limits login attempts to 5 per 15 minutes per IP and username and returns generic error messages to avoid user enumeration.
* Default `token` mode returns a one-time token and login URL with a one year TTL; tokens can optionally be tied to the requesting IP and/or user agent (via filters) and are consumed at `/wp-login.php?action=gn_token_login&token=...&u=...`.
* Optional `cookie` mode sets the normal WordPress auth cookies immediately for same-origin usage.
* Registration endpoint validates usernames, enforces unique emails, and requires passwords of at least eight characters.
* Forgot-password endpoint triggers the standard WordPress reset email while keeping responses generic when the account is unknown.
* Direct reset endpoint lets you verify users through a custom code and update their password immediately without sending the default email.
* Authenticated change-password endpoint lets logged-in users rotate their password after confirming the current one.
* Settings page at **Settings ▸ GN Login API** lets administrators whitelist a single external origin for CORS while keeping same-origin access functional.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/gn-password-login-api` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. (Optional) Navigate to **Settings ▸ GN Login API** to define an allowed CORS origin for cross-origin clients.

== Frequently Asked Questions ==

= Can I call the endpoint over HTTP? =

No. The endpoint enforces HTTPS and returns an error when accessed insecurely unless the developer-only `ALLOW_DEV_HTTP` constant is toggled to `true` while `WP_DEBUG` is enabled.

= How do I use the token login flow? =

Send a POST request with `mode` omitted or set to `token`. On success you will receive `token_login_url`; opening that URL in a browser within one year will set the auth cookies (respecting the `remember` flag) and redirect to the sanitized `redirect_to` value. You can opt in to locking the token to the requesting IP and/or user agent via filters when that restriction fits your deployment.

= Can I set cookies directly from another domain? =

Only when using the `cookie` mode from the same origin as the WordPress site. Cross-origin clients should use the token flow to avoid CORS credential issues.

= How do registration and password reset work? =

Send a POST request to `/wp-json/gn/v1/register` with `username`, `email`, and `password` (plus optional profile fields) to create a new account. To start a reset email, POST `/wp-json/gn/v1/forgot-password` with the user's username or email; the response message is intentionally generic to prevent account enumeration.

If you need to avoid the default email entirely, issue a one-time code with `GN_Password_Login_API::issue_reset_verification_code( $user_id )`, deliver it through your trusted channel, then call `POST /wp-json/gn/v1/reset-password` with the `login`, `verification_code`, and `new_password` fields.

== Hooks ==

* `gn_password_api_lock_token_to_ip`: return `true` to tie newly issued token URLs to the requesting IP address. Defaults to `false` to support mobile/native hand-offs where IPs may change between requests.
* `gn_password_api_lock_token_to_user_agent`: return `true` to require that the consuming browser/user agent matches the one that requested the token. Defaults to `false` to avoid mismatches between native apps and in-app browsers.
* `gn_password_api_validate_token_payload`: run final validation before the auth cookies are issued. Return `false` or a `WP_Error` to reject the token.

== Changelog ==

= 1.3.3 =
* Version bump for maintenance release.

= 1.3.2 =
* Allow token login URLs to work across differing IPs/user agents by default while providing filters to opt in to strict locking.
* Add a final validation filter that can veto token logins before cookies are issued.
* Return HTTP 403 responses when token validation hooks reject a login instead of HTTP 500.

= 1.3.1 =
* Version bump for maintenance release.

= 1.3.0 =
* Added an authenticated REST endpoint for users to change their own password after confirming the current credential.
* Automatically refreshes the session after a successful password change and documents the new flow.

= 1.2.0 =
* Added a REST endpoint for direct password resets with custom verification.
* Introduced helper method for issuing verification codes and documented the new flow.

= 1.1.0 =
* Added REST endpoints for user registration and initiating password resets.
* Documented new flows and strengthened password requirements for new accounts.

= 1.0.2 =
* Version bump for maintenance release.

= 1.0.1 =
* Initial public release of the hardened password login REST API.

== Upgrade Notice ==

= 1.3.3 =
Maintenance release.

= 1.3.2 =
Improves compatibility of token login URLs across browsers/devices and introduces new filters for optional strict locking.

= 1.3.1 =
Maintenance release.

= 1.3.0 =
Adds an authenticated change-password endpoint and refreshes the session after a successful update.

= 1.2.0 =
Adds a direct password reset endpoint and helper for issuing custom verification codes.

= 1.1.0 =
Adds registration and password reset endpoints for complete account management from external clients.

= 1.0.2 =
Version bump for maintenance release.

= 1.0.1 =
This release introduces the secure REST login endpoint with rate limiting, token hand-offs, and admin-configurable CORS support.
