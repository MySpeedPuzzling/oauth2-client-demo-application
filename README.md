# MySpeedPuzzling OAuth2 Client Demo

A minimal PHP application demonstrating the [OAuth2 Authorization Code flow](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) with the [MySpeedPuzzling](https://myspeedpuzzling.com) platform.

Built as a reference for external developers integrating with the MySpeedPuzzling API. Zero external dependencies — no Composer, no npm.

## What it does

1. User clicks **"Sign in with MySpeedPuzzling"**
2. Gets redirected to MySpeedPuzzling to authorize the application
3. MySpeedPuzzling redirects back with an authorization code
4. The app exchanges the code for an access token (server-to-server)
5. Fetches the user's profile via `GET /api/v1/me`
6. Displays a profile card with avatar, name, location, bio, and social links

## Prerequisites

- Docker (and Docker Compose)
- OAuth2 client credentials from MySpeedPuzzling

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/myspeedpuzzling/oauth2-client-demo-application.git
cd oauth2-client-demo-application

# 2. Configure your OAuth2 credentials
cp .env.example .env
# Edit .env and fill in your OAUTH2_CLIENT_ID and OAUTH2_CLIENT_SECRET

# 3. Start the application
docker compose up

# 4. Open in your browser
open http://localhost:8080
```

## OAuth2 Flow

```
┌──────────┐     1. /login          ┌──────────────────────┐
│          │ ──────────────────────▶ │                      │
│  Browser │                        │   MySpeedPuzzling     │
│          │ ◀────────────────────── │   Authorization      │
│          │     2. redirect with    │   Server             │
└──────────┘        ?code=...       └──────────────────────┘
     │                                        ▲
     │ 3. /callback?code=...&state=...        │
     ▼                                        │
┌──────────┐     4. POST /oauth2/token        │
│          │ ─────────────────────────────────▶│
│  Demo    │     (exchange code for token)     │
│  App     │ ◀─────────────────────────────────│
│          │     5. { access_token: ... }      │
│          │                                   │
│          │     6. GET /api/v1/me             │
│          │ ─────────────────────────────────▶│
│          │ ◀─────────────────────────────────│
│          │     7. { name, avatar, ... }      │
└──────────┘
```

### Key Security Concepts

- **State parameter** — A random value stored in the session and sent with the authorization request. Verified on callback to prevent CSRF attacks.
- **Server-side token exchange** — The authorization code is exchanged for an access token via a server-to-server request. The client secret never reaches the browser.
- **Output escaping** — All user data is escaped with `htmlspecialchars()` before rendering to prevent XSS.

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `OAUTH2_CLIENT_ID` | Yes | — | Your application's client ID |
| `OAUTH2_CLIENT_SECRET` | Yes | — | Your application's client secret |
| `OAUTH2_REDIRECT_URI` | No | `http://localhost:8080/callback` | Callback URL registered with MySpeedPuzzling |
| `OAUTH2_AUTHORIZE_URL` | No | `https://myspeedpuzzling.com/oauth2/authorize` | Authorization endpoint |
| `OAUTH2_TOKEN_URL` | No | `https://myspeedpuzzling.com/oauth2/token` | Token endpoint |
| `OAUTH2_API_BASE_URL` | No | `https://myspeedpuzzling.com` | API base URL |

## Project Structure

```
├── public/
│   └── index.php          # Single-file application (all routes + HTML)
├── .env.example            # Environment variables template
├── .github/
│   └── workflows/
│       └── release.yml     # CI/CD — build & push Docker image to GHCR
├── compose.yaml            # Local development (docker compose up)
├── Dockerfile              # Production image
└── README.md
```
