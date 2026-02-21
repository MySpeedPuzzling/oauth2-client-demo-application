<?php

declare(strict_types=1);

/**
 * MySpeedPuzzling OAuth2 Client Demo Application
 *
 * A minimal, single-file PHP application demonstrating the OAuth2 Authorization Code flow
 * with the MySpeedPuzzling platform. No external dependencies required — uses only
 * built-in PHP functions (curl, json_decode, session_*).
 *
 * @see https://myspeedpuzzling.com
 */

// ──────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────

// OAuth2 client credentials (required — set via environment variables)
$clientId = getenv('OAUTH2_CLIENT_ID') ?: '';
$clientSecret = getenv('OAUTH2_CLIENT_SECRET') ?: '';
$redirectUri = getenv('OAUTH2_REDIRECT_URI') ?: 'http://localhost:8080/callback';

// OAuth2 server endpoints (defaults point to MySpeedPuzzling production)
$authorizeUrl = getenv('OAUTH2_AUTHORIZE_URL') ?: 'https://myspeedpuzzling.com/oauth2/authorize';
$tokenUrl = getenv('OAUTH2_TOKEN_URL') ?: 'https://myspeedpuzzling.com/oauth2/token';
$apiBaseUrl = rtrim(getenv('OAUTH2_API_BASE_URL') ?: 'https://myspeedpuzzling.com', '/');

// ──────────────────────────────────────────────
// Helper Functions
// ──────────────────────────────────────────────

/**
 * Generate a cryptographically secure random string for CSRF state parameter.
 *
 * The "state" parameter is sent along with the authorization request and must be
 * verified when the user returns via the callback. This prevents CSRF attacks
 * where an attacker could trick a user into authorizing with the attacker's account.
 */
function generateCsrfState(int $length = 32): string
{
    return bin2hex(random_bytes($length));
}

/**
 * Send an HTTP POST request using cURL.
 *
 * Used for the token exchange step — sending the authorization code
 * to the token endpoint in exchange for an access token.
 *
 * @param array<string, string> $formData Form data to send as URL-encoded body
 * @param array<string, string> $headers Additional HTTP headers
 * @return array{body: string, httpCode: int}
 */
function sendPostRequest(string $url, array $formData, array $headers = []): array
{
    $curlHandle = curl_init($url);
    curl_setopt_array($curlHandle, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($formData),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => array_merge(['Content-Type: application/x-www-form-urlencoded'], $headers),
        CURLOPT_TIMEOUT => 10,
    ]);

    $responseBody = curl_exec($curlHandle);
    $httpCode = curl_getinfo($curlHandle, CURLINFO_HTTP_CODE);

    return ['body' => $responseBody, 'httpCode' => $httpCode];
}

/**
 * Send an HTTP GET request using cURL.
 *
 * Used for fetching the user's profile from the API after obtaining an access token.
 * The access token is sent in the Authorization header as a Bearer token.
 *
 * @param array<string, string> $headers Additional HTTP headers
 * @return array{body: string, httpCode: int}
 */
function sendGetRequest(string $url, array $headers = []): array
{
    $curlHandle = curl_init($url);
    curl_setopt_array($curlHandle, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_TIMEOUT => 10,
    ]);

    $responseBody = curl_exec($curlHandle);
    $httpCode = curl_getinfo($curlHandle, CURLINFO_HTTP_CODE);

    return ['body' => $responseBody, 'httpCode' => $httpCode];
}

/**
 * Escape a string for safe HTML output (XSS prevention).
 *
 * Every piece of user-supplied data MUST be escaped before rendering in HTML.
 * This is the single most important security measure in any web application.
 */
function escapeHtml(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ──────────────────────────────────────────────
// Route Handlers
// ──────────────────────────────────────────────

/**
 * Handle GET /login — Initiate OAuth2 Authorization Code flow.
 *
 * Generates a CSRF state token, stores it in the session, and redirects
 * the user to the MySpeedPuzzling authorization page.
 */
function handleLogin(string $clientId, string $redirectUri, string $authorizeUrl): never
{
    // Step 1: Generate a random "state" value and store it in the session.
    // We'll verify this value when the user returns via /callback to prevent CSRF attacks.
    $state = generateCsrfState();
    $_SESSION['oauth2_state'] = $state;

    // Step 2: Build the authorization URL with required parameters:
    // - response_type=code  → We want an authorization code (not an implicit token)
    // - client_id           → Identifies our application to the OAuth2 server
    // - redirect_uri        → Where the user should be sent after authorizing
    // - state               → CSRF protection token
    $queryString = http_build_query([
        'response_type' => 'code',
        'client_id' => $clientId,
        'redirect_uri' => $redirectUri,
        'scope' => 'profile:read collections:read',
        'state' => $state,
    ]);

    // Step 3: Redirect the user to the OAuth2 authorization page.
    // The user will see a consent screen and choose to allow or deny access.
    header("Location: {$authorizeUrl}?{$queryString}");
    exit;
}

/**
 * Handle GET /callback — Process the OAuth2 server's response.
 *
 * Validates the CSRF state, exchanges the authorization code for an access token,
 * fetches the user's profile, and stores it in the session.
 */
function handleCallback(string $clientId, string $clientSecret, string $redirectUri, string $tokenUrl, string $apiBaseUrl): never
{
    // Step 1: Verify the state parameter to prevent CSRF attacks.
    // If the state doesn't match what we stored in session, someone may be trying
    // to trick the user into connecting an attacker-controlled account.
    $receivedState = $_GET['state'] ?? '';
    $expectedState = $_SESSION['oauth2_state'] ?? '';

    if ($receivedState === '' || $receivedState !== $expectedState) {
        http_response_code(403);
        echo 'Invalid state parameter — possible CSRF attack.';
        exit;
    }

    // Clean up the state from session (it's single-use)
    unset($_SESSION['oauth2_state']);

    // Check if the user denied access or if an error occurred.
    // Store the error in session and redirect to homepage to show it inline.
    if (isset($_GET['error'])) {
        $_SESSION['oauth2_error'] = $_GET['error'];
        $_SESSION['oauth2_error_description'] = $_GET['error_description'] ?? null;

        header('Location: /');
        exit;
    }

    // Step 2: Extract the authorization code from the callback URL.
    // This code is short-lived and can only be used once.
    $authorizationCode = $_GET['code'] ?? '';

    if ($authorizationCode === '') {
        http_response_code(400);
        echo 'Missing authorization code.';
        exit;
    }

    // Step 3: Exchange the authorization code for an access token.
    // This is a server-to-server POST request (the user never sees the client secret).
    // The token endpoint verifies:
    //   - The authorization code is valid and hasn't been used before
    //   - The client_id and client_secret match a registered application
    //   - The redirect_uri matches what was used in the authorization request
    $tokenResponse = sendPostRequest($tokenUrl, [
        'grant_type' => 'authorization_code',
        'code' => $authorizationCode,
        'redirect_uri' => $redirectUri,
        'client_id' => $clientId,
        'client_secret' => $clientSecret,
    ]);

    if ($tokenResponse['httpCode'] !== 200) {
        http_response_code(502);
        echo 'Token exchange failed (HTTP ' . $tokenResponse['httpCode'] . ")\n\n" . $tokenResponse['body'];
        exit;
    }

    $tokenData = json_decode($tokenResponse['body'], true);
    $accessToken = $tokenData['access_token'] ?? null;

    if ($accessToken === null) {
        http_response_code(502);
        echo 'No access token in response.';
        exit;
    }

    // Step 4: Use the access token to fetch the user's profile from the API.
    // The access token is sent as a Bearer token in the Authorization header.
    $profileResponse = sendGetRequest("{$apiBaseUrl}/api/v1/me", [
        "Authorization: Bearer {$accessToken}",
        'Accept: application/json',
    ]);

    if ($profileResponse['httpCode'] !== 200) {
        http_response_code(502);
        echo 'Failed to fetch profile (HTTP ' . $profileResponse['httpCode'] . ')';
        exit;
    }

    $profile = json_decode($profileResponse['body'], true);

    // Step 5: Store the profile in the session so we can display it on the home page.
    // In a real application, you might also store the access token for further API calls,
    // and handle token refresh if a refresh_token was provided.
    $_SESSION['profile'] = $profile;

    header('Location: /');
    exit;
}

/**
 * Handle GET /logout — Destroy the session and redirect to the home page.
 */
function handleLogout(): never
{
    session_destroy();

    header('Location: /');
    exit;
}

/**
 * Handle GET / — Show the login button or the authenticated user's profile card.
 */
function handleHome(): never
{
    $profile = $_SESSION['profile'] ?? null;

    // Pull error from session (one-time flash message)
    $error = $_SESSION['oauth2_error'] ?? null;
    $errorDescription = $_SESSION['oauth2_error_description'] ?? null;
    unset($_SESSION['oauth2_error'], $_SESSION['oauth2_error_description']);

    renderPage($profile, $error, $errorDescription);
    exit;
}

// ──────────────────────────────────────────────
// Session & Routing
// ──────────────────────────────────────────────

session_start();

$requestPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

match ($requestPath) {
    '/login' => handleLogin($clientId, $redirectUri, $authorizeUrl),
    '/callback' => handleCallback($clientId, $clientSecret, $redirectUri, $tokenUrl, $apiBaseUrl),
    '/logout' => handleLogout(),
    '/' => handleHome(),
    default => handleHome(),
};

// ──────────────────────────────────────────────
// HTML Rendering
// ──────────────────────────────────────────────

/**
 * Render the full HTML page.
 *
 * Shows either a login button (when not authenticated)
 * or a profile card with user details (when authenticated).
 *
 * @param array<string, mixed>|null $profile
 */
function renderPage(?array $profile, ?string $error = null, ?string $errorDescription = null): void
{
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MySpeedPuzzling OAuth2 Demo</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script>
            tailwind.config = {
                theme: {
                    extend: {
                        colors: {
                            brand: {
                                DEFAULT: '#E9746E',
                                dark: '#D4625C',
                                light: '#F5A8A4',
                                50: '#FDF2F1',
                            }
                        }
                    }
                }
            }
        </script>
    </head>
    <body class="bg-gray-100 p-4 pt-16 sm:pt-24">
        <div class="w-full max-w-md mx-auto">

            <?php if ($error !== null): ?>
                <?php renderErrorBanner($error, $errorDescription); ?>
            <?php endif; ?>

            <?php if ($profile === null): ?>
                <?php renderLoginScreen(); ?>
            <?php else: ?>
                <?php renderProfileCard($profile); ?>
            <?php endif; ?>

            <!-- Footer -->
            <p class="text-center text-xs text-gray-400 mt-6">
                OAuth2 Authorization Code Flow Demo &middot;
                <a href="https://github.com/myspeedpuzzling/oauth2-client-demo-application"
                   target="_blank"
                   class="underline hover:text-gray-600">Source on GitHub</a>
            </p>
        </div>
    </body>
    </html>
    <?php
}

/**
 * Render the login screen with a sign-in button and explanation.
 */
function renderLoginScreen(): void
{
    ?>
    <div class="bg-white rounded-2xl shadow-lg p-8 text-center">
        <div class="mb-6">
            <img src="https://myspeedpuzzling.com/img/speedpuzzling-logo.svg"
                 alt="MySpeedPuzzling"
                 class="h-10 mx-auto mb-4">
            <p class="text-gray-500 text-sm">OAuth2 Authorization Code Flow Demo</p>
        </div>

        <a href="/login"
           class="inline-flex items-center justify-center gap-2 w-full bg-brand hover:bg-brand-dark text-white font-semibold py-3 px-6 rounded-lg transition-colors">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"/>
            </svg>
            Sign in with MySpeedPuzzling
        </a>

        <div class="mt-8 text-left text-xs text-gray-400 space-y-2">
            <p class="font-semibold text-gray-500">How it works:</p>
            <ol class="list-decimal list-inside space-y-1">
                <li>Click the button to go to MySpeedPuzzling</li>
                <li>Authorize this demo application</li>
                <li>Get redirected back with your profile</li>
            </ol>
        </div>
    </div>
    <?php
}

/**
 * Render an inline error banner above the login screen.
 */
function renderErrorBanner(string $error, ?string $errorDescription): void
{
    ?>
    <div class="bg-red-50 border border-red-200 rounded-2xl p-4 mb-4 flex items-start gap-3">
        <div class="shrink-0 w-9 h-9 rounded-full bg-red-100 flex items-center justify-center mt-0.5">
            <svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M6 18L18 6M6 6l12 12"/>
            </svg>
        </div>
        <div class="min-w-0">
            <p class="text-sm font-semibold text-red-800">Authorization Denied</p>
            <p class="text-sm text-red-600 mt-0.5">
                <?= escapeHtml($errorDescription ?? 'The authorization request was not completed.') ?>
            </p>
            <span class="inline-block mt-2 text-xs font-mono bg-red-100 text-red-400 px-2 py-0.5 rounded">
                <?= escapeHtml($error) ?>
            </span>
        </div>
    </div>
    <?php
}

/**
 * Render the authenticated user's profile card.
 *
 * @param array<string, mixed> $profile
 */
function renderProfileCard(array $profile): void
{
    $socialLinks = collectSocialLinks($profile);

    ?>
    <div class="bg-white rounded-2xl shadow-lg overflow-hidden">
        <!-- Header -->
        <div class="bg-gradient-to-r from-brand to-brand-dark px-6 py-4 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <img src="https://myspeedpuzzling.com/img/speedpuzzling-logo.svg"
                     alt="MySpeedPuzzling"
                     class="h-6">
                <span class="text-white font-bold">Profile</span>
            </div>
            <a href="/logout"
               class="text-brand-light hover:text-white text-sm font-medium transition-colors">
                Sign out
            </a>
        </div>

        <div class="p-6">
            <!-- Avatar & Name -->
            <div class="flex items-center gap-4 mb-6">
                <?php if (!empty($profile['avatar'])): ?>
                    <img src="<?= escapeHtml($profile['avatar']) ?>"
                         alt="Avatar"
                         class="w-16 h-16 rounded-full object-cover ring-2 ring-brand-50">
                <?php else: ?>
                    <div class="w-16 h-16 rounded-full bg-brand-50 flex items-center justify-center">
                        <span class="text-brand text-xl font-bold">
                            <?= escapeHtml(mb_substr($profile['name'] ?? '?', 0, 1)) ?>
                        </span>
                    </div>
                <?php endif; ?>

                <div>
                    <?php if (!empty($profile['name'])): ?>
                        <h2 class="text-xl font-bold text-gray-900"><?= escapeHtml($profile['name']) ?></h2>
                    <?php endif; ?>

                    <?php if (!empty($profile['player_code'])): ?>
                        <span class="inline-block mt-1 text-xs font-mono bg-gray-100 text-gray-500 px-2 py-0.5 rounded">
                            <?= escapeHtml($profile['player_code']) ?>
                        </span>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Details -->
            <div class="space-y-3 text-sm">
                <?php if (!empty($profile['country']) || !empty($profile['city'])): ?>
                    <div class="flex items-center gap-2 text-gray-600">
                        <svg class="w-4 h-4 text-gray-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                  d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"/>
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                  d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"/>
                        </svg>
                        <span>
                            <?= escapeHtml(implode(', ', array_filter([$profile['city'] ?? null, $profile['country'] ?? null]))) ?>
                        </span>
                    </div>
                <?php endif; ?>

                <?php if (!empty($profile['bio'])): ?>
                    <div class="flex items-start gap-2 text-gray-600">
                        <svg class="w-4 h-4 text-gray-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                  d="M4 6h16M4 12h16M4 18h7"/>
                        </svg>
                        <span><?= escapeHtml($profile['bio']) ?></span>
                    </div>
                <?php endif; ?>

                <?php if (!empty($profile['member_since'])): ?>
                    <div class="flex items-center gap-2 text-gray-600">
                        <svg class="w-4 h-4 text-gray-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                  d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
                        </svg>
                        <span>Member since <?= escapeHtml($profile['member_since']) ?></span>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Social Links -->
            <?php if (!empty($socialLinks)): ?>
                <div class="mt-4 pt-4 border-t border-gray-100">
                    <p class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Social</p>
                    <div class="flex flex-wrap gap-2">
                        <?php foreach ($socialLinks as $socialLink): ?>
                            <a href="<?= escapeHtml($socialLink['url']) ?>"
                               target="_blank"
                               rel="noopener noreferrer"
                               class="text-xs bg-gray-100 hover:bg-gray-200 text-gray-600 px-3 py-1 rounded-full transition-colors">
                                <?= escapeHtml($socialLink['label']) ?>
                            </a>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <!-- Raw Response (collapsible, for developers) -->
        <div class="border-t border-gray-100 px-6 py-4">
            <details>
                <summary class="text-xs font-semibold text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-600">
                    Raw API Response
                </summary>
                <pre class="mt-3 text-xs bg-gray-50 rounded-lg p-4 overflow-x-auto text-gray-600"><?= escapeHtml(json_encode($profile, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) ?></pre>
            </details>
        </div>
    </div>
    <?php
}

/**
 * Collect available social links from the user's profile.
 *
 * @param array<string, mixed> $profile
 * @return list<array{label: string, url: string}>
 */
function collectSocialLinks(array $profile): array
{
    $socialLinks = [];

    if (!empty($profile['facebook'])) {
        $socialLinks[] = ['label' => 'Facebook', 'url' => $profile['facebook']];
    }

    if (!empty($profile['instagram'])) {
        $socialLinks[] = ['label' => 'Instagram', 'url' => $profile['instagram']];
    }

    if (!empty($profile['youtube'])) {
        $socialLinks[] = ['label' => 'YouTube', 'url' => $profile['youtube']];
    }

    return $socialLinks;
}
