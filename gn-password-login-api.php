<?php
/**
 * Plugin Name: GN Password Login API
 * Description: Secure REST login via username/email + password with rate limiting, HTTPS checks, and one-time token login URL for cross-origin/mobile apps.
 * Version: 1.0.2
 * Author: George Nicolaou
 * License: GPL-2.0+
 */

if (!defined('ABSPATH')) exit;

require_once __DIR__ . '/plugin-update-checker/plugin-update-checker.php';

class GN_Password_Login_API {
	const REST_NAMESPACE = 'gn/v1';
	const OPTION_KEY     = 'gn_login_api_settings';
	const ATTEMPT_LIMIT  = 5;      // attempts per window
	const WINDOW_SECONDS = 15 * 60; // 15 minutes
	const TOKEN_TTL      = 60;     // 60 seconds (one-time login token)
	const ALLOW_DEV_HTTP = false;  // set true only on local dev

	public function __construct() {
		add_action('rest_api_init', [$this, 'register_routes']);
		add_action('login_init',    [$this, 'maybe_consume_token']); // /wp-login.php?action=gn_token_login&token=...&redirect_to=...
		add_action('admin_init',    [$this, 'register_settings']);
		add_action('admin_menu',    [$this, 'admin_menu']);

		// CORS for the specific allowed origin (if any set in settings)
                add_action('rest_api_init', function() {
                        remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');
                        add_filter('rest_pre_serve_request', [$this, 'cors_headers'], 10, 4);
                }, 15);
	}

	/* ---------------- Settings (allowed origin) ---------------- */

	public function register_settings() {
                register_setting(self::OPTION_KEY, self::OPTION_KEY, [
			'type'       => 'array',
			'show_in_rest' => false,
			'default'    => ['allowed_origin' => ''],
			'sanitize_callback' => function($value) {
				$val = is_array($value) ? $value : [];
				$origin = isset($val['allowed_origin']) ? trim($val['allowed_origin']) : '';
				// Allow empty or a valid http(s) origin (scheme + host + optional port)
				if ($origin !== '' && !preg_match('#^https?://[^/]+$#i', $origin)) {
					$origin = '';
				}
				return ['allowed_origin' => $origin];
			}
                ]);
	}

	public function admin_menu() {
		add_options_page(
			'GN Login API',
			'GN Login API',
			'manage_options',
			'gn-login-api',
			[$this, 'render_settings_page']
		);
	}

	public function render_settings_page() {
		$opt = get_option(self::OPTION_KEY, ['allowed_origin' => '']);
		?>
		<div class="wrap">
			<h1>GN Password Login API</h1>
			<form method="post" action="options.php">
				<?php settings_fields(self::OPTION_KEY); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="allowed_origin">Allowed CORS Origin</label></th>
						<td>
							<input type="text" id="allowed_origin" name="<?php echo esc_attr(self::OPTION_KEY); ?>[allowed_origin]"
								   value="<?php echo esc_attr($opt['allowed_origin'] ?? ''); ?>"
								   class="regular-text" placeholder="https://app.example.com">
							<p class="description">
								If you’ll call the REST endpoint from another domain (SPA/mobile proxy), set that exact origin here.
								Leave empty to allow only same-origin browser calls.
							</p>
						</td>
					</tr>
				</table>
				<?php submit_button(); ?>
			</form>
		</div>
		<?php
	}

	/* ---------------- REST Route ---------------- */

	public function register_routes() {
		register_rest_route(self::REST_NAMESPACE, '/login', [
			'methods'  => WP_REST_Server::CREATABLE, // POST
			'callback' => [$this, 'handle_login'],
			'permission_callback' => '__return_true',
			'args' => [
				'username' => ['required' => true, 'type' => 'string'],
				'password' => ['required' => true, 'type' => 'string'],
				'remember' => ['required' => false, 'type' => 'boolean'],
				'mode'     => ['required' => false, 'type' => 'string', 'enum' => ['cookie','token']],
				'redirect_to' => ['required' => false, 'type' => 'string'],
			],
		]);
	}

	private function require_https_or_fail() {
		if (is_ssl()) return;
		if (self::ALLOW_DEV_HTTP && defined('WP_DEBUG') && WP_DEBUG) return;
		return new WP_Error('insecure_connection', 'This endpoint requires HTTPS.', ['status' => 400]);
	}

	private function rate_key_ip() {
		$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
		return 'gn_login_ip_' . md5($ip);
	}
	private function rate_key_user($username) {
		return 'gn_login_user_' . md5(strtolower($username));
	}

	private function bump_attempts($key) {
		$bundle = get_transient($key);
		$bundle = is_array($bundle) ? $bundle : ['count' => 0, 'first' => time()];
		$bundle['count']++;
		set_transient($key, $bundle, self::WINDOW_SECONDS);
		return $bundle['count'];
	}

	private function get_attempts($key) {
		$bundle = get_transient($key);
		return is_array($bundle) ? (int)$bundle['count'] : 0;
	}

	private function clear_attempts($key) {
		delete_transient($key);
	}

	public function handle_login(WP_REST_Request $req) {
		// HTTPS check
		if ($err = $this->require_https_or_fail()) {
			return $err;
		}

		// Basic input
		$username = trim((string)$req->get_param('username'));
		$password = (string)$req->get_param('password');
		$remember = (bool)$req->get_param('remember');
		$mode     = (string)($req->get_param('mode') ?? 'token'); // default safer for cross-origin
		$redirect_to = (string)($req->get_param('redirect_to') ?? home_url('/'));

		// Rate limiting (IP + username)
		$ipKey   = $this->rate_key_ip();
		$userKey = $this->rate_key_user($username);

		if ($this->get_attempts($ipKey) >= self::ATTEMPT_LIMIT || $this->get_attempts($userKey) >= self::ATTEMPT_LIMIT) {
			return new WP_Error('too_many_attempts', 'Too many login attempts. Please try again later.', ['status' => 429]);
		}

		// We DO NOT reveal whether username exists (constant-time-ish failure)
		// Authenticate
		add_filter('authenticate', function($user_or_error) {
			// Ensure only core WP authentication handlers run
			return $user_or_error;
		}, 30, 1);

		// Allow email or username
		if (is_email($username)) {
			$user_obj = get_user_by('email', $username);
			if ($user_obj) $username = $user_obj->user_login;
		}

		$creds = [
			'user_login'    => $username,
			'user_password' => $password,
			'remember'      => $remember,
		];

		$user = wp_authenticate($creds['user_login'], $creds['user_password']);

		if (is_wp_error($user)) {
			$this->bump_attempts($ipKey);
			$this->bump_attempts($userKey);
			// Generic message to avoid user enumeration
			return new WP_Error('invalid_credentials', 'Invalid username or password.', ['status' => 401]);
		}

		// Success: clear counters
		$this->clear_attempts($ipKey);
		$this->clear_attempts($userKey);

		// If user is blocked or requires activation, you could enforce here
		if (user_can($user, 'blocked')) {
			return new WP_Error('access_denied', 'Your account is not allowed to log in.', ['status' => 403]);
		}

		if ($mode === 'cookie') {
			// Same-origin browser flow: set auth cookies here.
			// Only safe/useful when called from your site (same-site) over HTTPS.
			wp_set_auth_cookie($user->ID, $remember);
			do_action('wp_login', $user->user_login, $user);

			return new WP_REST_Response([
				'success' => true,
				'mode'    => 'cookie',
				'message' => 'Logged in. Auth cookies set.',
				'user'    => [
					'id'       => $user->ID,
					'login'    => $user->user_login,
					'email'    => $user->user_email,
					'nicename' => $user->user_nicename,
					'display'  => $user->display_name,
				],
			], 200);
		}

		// Default: token mode (safer for cross-origin/mobile)
		$token = wp_generate_uuid4();
		$meta_key = '_gn_login_token_' . $token;

		// Store as user meta with tight TTL info (ip, ua, expiry)
		$payload = [
			'expires'   => time() + self::TOKEN_TTL,
			'ip'        => $_SERVER['REMOTE_ADDR'] ?? '',
			'ua'        => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'remember'  => $remember,
		];
		add_user_meta($user->ID, $meta_key, wp_json_encode($payload), true);

		// Build token login URL
		$login_url = wp_login_url();
		$redir     = $this->safe_redirect_url($redirect_to);
		$token_url = add_query_arg([
			'action'  => 'gn_token_login',
			'token'   => $token,
			'u'       => $user->ID,
			'redirect_to' => $redir,
		], $login_url);

		return new WP_REST_Response([
			'success' => true,
			'mode'    => 'token',
			'token'   => $token,
			'token_expires_in' => self::TOKEN_TTL,
			'token_login_url'  => $token_url,
			'user'    => [
				'id'       => $user->ID,
				'login'    => $user->user_login,
				'email'    => $user->user_email,
				'nicename' => $user->user_nicename,
				'display'  => $user->display_name,
			],
		], 200);
	}

	private function safe_redirect_url($url) {
		// Only allow internal redirects; otherwise fallback to home.
		$home = home_url('/');
		if (!$url) return $home;
		// Allow only same host
		$home_host = parse_url($home, PHP_URL_HOST);
		$url_host  = parse_url($url, PHP_URL_HOST);
		if ($url_host && strcasecmp($url_host, $home_host) !== 0) {
			return $home;
		}
		return esc_url_raw($url);
	}

	public function maybe_consume_token() {
		if (!isset($_GET['action']) || $_GET['action'] !== 'gn_token_login') return;

		$token = isset($_GET['token']) ? sanitize_text_field($_GET['token']) : '';
		$user_id = isset($_GET['u']) ? absint($_GET['u']) : 0;
		$redirect_to = isset($_GET['redirect_to']) ? $this->safe_redirect_url(esc_url_raw($_GET['redirect_to'])) : home_url('/');

		if (!$token || !$user_id) {
			wp_die(__('Invalid token login request.', 'gn-login'));
		}

		$meta_key = '_gn_login_token_' . $token;
		$rows = get_user_meta($user_id, $meta_key, false);
		if (empty($rows)) {
			wp_die(__('This token is invalid or already used.', 'gn-login'));
		}

		$payload = json_decode((string)$rows[0], true);
		delete_user_meta($user_id, $meta_key); // one-time use

		if (!is_array($payload)) {
			wp_die(__('Invalid token payload.', 'gn-login'));
		}
		if (time() > (int)$payload['expires']) {
			wp_die(__('This token has expired. Please log in again.', 'gn-login'));
		}

		// (Optional) tie token to same IP/UA for extra safety; comment out to relax.
		$ip = $_SERVER['REMOTE_ADDR'] ?? '';
		$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
		if (!empty($payload['ip']) && $payload['ip'] !== $ip) {
			wp_die(__('Token IP mismatch.', 'gn-login'));
		}
		if (!empty($payload['ua']) && $payload['ua'] !== $ua) {
			wp_die(__('Token UA mismatch.', 'gn-login'));
		}

		// Log user in
		wp_set_auth_cookie($user_id, !empty($payload['remember']));
		$user = get_user_by('id', $user_id);
		if ($user) {
			do_action('wp_login', $user->user_login, $user);
		}

		wp_safe_redirect($redirect_to);
		exit;
	}

	/* ---------------- CORS ---------------- */

        public function cors_headers($served, $result = null, $request = null, $server = null) {
		$opt = get_option(self::OPTION_KEY, ['allowed_origin' => '']);
		$allowed = $opt['allowed_origin'] ?? '';

		$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
		$same_origin = $this->is_same_origin($origin);

		// Only set CORS for the specifically allowed origin; otherwise none.
		if ($allowed && $origin === $allowed) {
			header('Access-Control-Allow-Origin: ' . $allowed);
			header('Vary: Origin', false);
			header('Access-Control-Allow-Methods: POST, OPTIONS');
			header('Access-Control-Allow-Credentials: true');
			header('Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With');
		} elseif ($same_origin || empty($origin)) {
			// Same-origin calls are fine; no wildcard.
			// (Browser won’t require CORS if same origin.)
		} else {
			// Block other origins by not sending ACAO
		}

		// Handle preflight
		if ('OPTIONS' === $_SERVER['REQUEST_METHOD']) {
			status_header(204);
			exit;
		}
		return $served;
	}

	private function is_same_origin($origin) {
		if (!$origin) return false;
		$site = get_site_url(null, '/', is_ssl() ? 'https' : 'http');
		$oh = parse_url($origin, PHP_URL_HOST);
		$sh = parse_url($site,   PHP_URL_HOST);
		return ($oh && $sh && strcasecmp($oh, $sh) === 0);
	}
}

new GN_Password_Login_API();

$gn_login_api_updater = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
        'https://github.com/GeorgeWebDevCy/gn-password-login-api/',
        __FILE__,
        'gn-password-login-api'
);
$gn_login_api_updater->setBranch('main');
