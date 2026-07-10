# **Soyez Sécurisé**
> *"Be Secure"* - A zero-knowledge password manager built from scratch by a self-taught 15-year-old developer.

Built with WebCrypto APIs, FastAPI, Redis, PostgreSQL, signed requests, and a custom authentication flow.

---

## What It Does

Soyez Sécurisé stores, retrieves, lists, hints, and deletes encrypted password records through a browser interface. The core guarantee is still the same: **the server never sees your plaintext passwords, never sees your vault key, and cannot decrypt your vault data even with database access.**

Sensitive vault data is encrypted in the browser before it touches the network. The backend receives encrypted blobs, request signatures, session IDs, and metadata needed to enforce access control.

## New Features

- Split signup flow: `/newuser1` starts email verification, then `/newuser2` completes account creation with the OTP, Argon2id auth hash, salt, and email.
- Split login flow: `/login` issues the challenge and salt, then `/login2` verifies the HMAC signature plus OTP and returns a short-lived `session_id`.
- Session enforcement: protected vault/profile routes require the active Redis-backed `session_id`; expired sessions return `{"ERROR": "Session expired, login again"}`.
- OTP methods: users can protect login with either email OTP or authenticator-app TOTP during setup.
- Password hints: store an optional client-encoded hint with a vault record and retrieve it through the same nonce/HMAC/session flow.
- Profile dashboard: shows email, 2FA status, session TTL, stored credential count, and saved service identifiers.
- Account deletion: signed two-step account removal deletes user records, email, OTP setup, vault entries, hints, IP tracking, and the active session.
- Email alerts: Resend-powered templates for OTP delivery, welcome messages, login notifications, password retrieval, and deletion alerts.
- Frontend session helpers: `api.js` centralizes session storage, auth-state events, HMAC signing helpers, and route guards.
- UI refresh: public beta badge, mobile-focused action hub, signup/login step panels, progress feedback, tooltips, home prompt, password hint screen, and improved OTP setup page.
- Backend hardening: per-request DB connections, access logging middleware, stricter request-id/session-id patterns, trusted-proxy IP parsing, security headers, CSP, and one-time nonce cleanup.

---

## Architecture

<img width="1536" height="1024" alt="FLOW" src="https://github.com/user-attachments/assets/fb3bd749-046c-4b76-afb2-40adb34a0803" />

## Security Design

### Cryptographic Stack

| Layer | Algorithm | Where |
|---|---|---|
| Password hashing | Argon2id `(t=4, m=65536, p=4, len=32)` | Browser signup/login |
| Key separation | HKDF-SHA256 | Browser |
| Request authentication | HMAC-SHA256 | Browser signs, server verifies |
| Credential encryption | AES-256-GCM with random IV | Browser only |
| OTP secret storage | ChaCha20-Poly1305 | Server-side at rest |
| OTP verification | TOTP via pyotp or email OTP | Server |
| Session tracking | 32-byte hex session ID with Redis TTL | Server verifies |

### Nonce, Session, and Replay Protection

Authenticated actions still use one-time server-issued nonces with a 5-minute Redis TTL. The client signs the nonce with the derived HMAC auth key, and the server deletes or expires nonce state after use.

After login, the server also stores `session_id:{username}` in Redis with the session value, request ID, IP, and a 30-minute TTL. Protected routes must include the current `session_id`; if it is missing, expired, or mismatched, the backend returns:

```json
{"ERROR": "Session expired, login again"}
```

### Timing Attack Prevention

Endpoints that check usernames still use `time_equilizer()` to pad responses to a fixed minimum duration. This makes valid and invalid usernames harder to distinguish by timing alone.

### Rate Limiting & IP Blocking

- Per-username request counters in Redis
- Temporary account blocking after repeated failed attempts
- IP-level blocking through `check_block.py`
- Structured logs for login, database, system, OTP, and access events
- Trusted proxy handling for `x-forwarded-for`

### Vault Key Safety

`window.vaultkey` lives **in browser RAM only**. It is never written to `localStorage`, `sessionStorage`, cookies, or sent to the server. A page reload destroys it intentionally, so the user must log in again to decrypt vault data.

The browser stores the HMAC auth key hex and `session_id` locally so signed operations can continue during the active session. The vault encryption key remains memory-only.

---

## Possible Vulnerability: XSS

Possible vulnerability: xss.

The frontend stores authentication material in `localStorage` (`authkey`, `username`, `session_id`) while keeping the vault AES key in RAM. This means a real cross-site scripting bug could be severe: injected JavaScript might read stored auth/session values, call signed endpoints, or interact with the in-memory vault key while the page is open.

Current mitigations include `innerText`/`textContent` for most dynamic UI rendering, backend validation patterns, and a Content Security Policy. The CSP still allows `'unsafe-inline'` for styles, and the project should continue auditing every `innerHTML`/HTML-template usage, third-party script, and user-controlled value before treating the app as production hardened.

Recommended next steps:

- Keep all user-controlled output rendered with `textContent` or `innerText`.
- Avoid adding dynamic `innerHTML`; if HTML is required, sanitize with a trusted sanitizer.
- Remove inline event handlers and tighten CSP further when the frontend is ready.
- Consider moving session handling toward HttpOnly/SameSite cookies or another design that reduces JavaScript-readable session exposure.
- Add automated checks for DOM XSS sinks such as `innerHTML`, `insertAdjacentHTML`, `outerHTML`, and unsafe URL writes.

---

## Database Schema

```sql
public.users
  id          SERIAL PRIMARY KEY
  username    TEXT UNIQUE
  hash        TEXT        -- HMAC-SHA256 auth key hex, not the master password

public.salt
  id          SERIAL PRIMARY KEY
  userid      INTEGER REFERENCES users(id)
  salt        TEXT        -- Argon2id salt hex

public.stored
  id          SERIAL PRIMARY KEY
  userid      INTEGER REFERENCES users(id)
  servicename TEXT
  accountusername TEXT
  encdata     TEXT        -- base64(IV || AES-256-GCM ciphertext)

public.hints
  id          SERIAL PRIMARY KEY
  userid      INTEGER REFERENCES users(id)
  password_id INTEGER REFERENCES stored(id)
  hint        TEXT        -- client-encoded hint

public.twofa
  id          SERIAL PRIMARY KEY
  userid      INTEGER REFERENCES users(id)
  enabled     BOOLEAN
  method      TEXT        -- gmail or totp
  secret      TEXT        -- encrypted TOTP secret when method is totp
  salt        TEXT        -- base64(nonce || tag)

public.emails
  id          SERIAL PRIMARY KEY
  userid      INTEGER REFERENCES users(id)
  email       TEXT

public.iptracking
  id          SERIAL PRIMARY KEY
  userid      INTEGER REFERENCES users(id)
  ip          TEXT
```

---

## API Endpoints

All endpoints are `POST`. The backend runs on FastAPI, usually at `localhost:8000`.

| Endpoint | Purpose |
|---|---|
| `POST /newuser1` | Signup step 1: validate username/email and send registration OTP |
| `POST /newuser2` | Signup step 2: verify OTP and create user, salt, hash, and email records |
| `POST /login` | Login step 1: return nonce, salt, request ID, and OTP challenge state |
| `POST /login2` | Login step 2: verify HMAC + OTP, then create `session_id` |
| `POST /enableotp` | OTP setup step 1: issue signed setup challenge |
| `POST /enable_otp2` | OTP setup step 2: enable email OTP or TOTP |
| `POST /storepassword` | Store step 1: issue nonce for a vault write |
| `POST /storepassword2` | Store step 2: verify HMAC/session and store encrypted blob + optional hint |
| `POST /getenc` | Retrieve step 1: issue nonce for a vault read |
| `POST /getenc2` | Retrieve step 2: verify HMAC/session and return encrypted blob |
| `POST /list` | List step 1: issue nonce for listing |
| `POST /list2` | List step 2: verify HMAC/session and return service/user identifiers |
| `POST /hint` | Hint step 1: issue nonce for hint retrieval |
| `POST /hint2` | Hint step 2: verify HMAC/session and return stored hint |
| `POST /delete` | Delete step 1: issue nonce for vault item deletion |
| `POST /delete2` | Delete step 2: verify HMAC/session and delete the vault item |
| `POST /profile/status` | Profile step 1: issue nonce for profile status |
| `POST /profile/status2` | Profile step 2: verify HMAC/session and return account/vault status |
| `POST /acc-delete` | Account deletion step 1: issue nonce |
| `POST /acc-delete2` | Account deletion step 2: verify HMAC/session and delete account data |

---

## Project Structure

```text
├── README.md
├── LICENSE
└── soyezsecurise/
    ├── soyezsecurise-backend/
    │   ├── main.py          # FastAPI routes, auth/session checks, vault operations
    │   ├── check_block.py   # IP blocking logic
    │   ├── logger.py        # Structured login/db/sys/otp/access logs
    │   ├── gmail.py         # Resend email templates and alerts
    │   ├── vault_email.py   # Email template helpers
    │   ├── filter.py        # Log/filter utility
    │   └── requirements.txt
    └── soyezsecurise-frontend/
        ├── index.html
        ├── enable-otp.html
        ├── assets/css/main.css
        └── assets/js/
            ├── api.js          # Session, signing, encoding, auth helpers
            ├── signup.js       # Two-step signup and OTP verification
            ├── login.js        # Two-step login, key derivation, session storage
            ├── enable_otp.js   # Email/TOTP setup flow
            ├── store.js        # Encrypt and store credentials
            ├── get.js          # Retrieve and decrypt credentials
            ├── list.js         # Vault listing
            ├── hint.js         # Password hint retrieval
            ├── delete.js       # Vault item deletion
            ├── profile.js      # Profile/session/account deletion UI
            ├── menu.js         # Reactive auth menu state
            ├── progress.js     # Status/progress UI helpers
            ├── tooltips.js     # Tooltip behavior
            ├── home_prompt.js  # Homepage signup/login prompt
            ├── quote.js
            └── otpanswer.js
```

---

## Known Limitations (Beta)

- This is still a learning project and has not been audited by a security professional.
- `localhost:8000`/deployment API configuration still needs a clean environment-based setup.
- HTTPS is mandatory before real deployment; do not use this over plain HTTP.
- The backend still relies on custom auth/security logic that needs formal review.
- Local JavaScript-readable auth/session material increases XSS impact.
- Email templates and alert links should be reviewed before production use.
- No account recovery exists by design; if the master password is lost, vault data is unrecoverable.

---

## Demo

Visit https://soyezsecurise.com/

---

## Author

Built by **@fahisxd** on https://instagram.com or discord

Designed and implemented independently: the cryptographic architecture, nonce/HMAC auth flow, key separation scheme, frontend, and backend were all figured out without following a tutorial for any of it.

---

## V1 / Beta Notice

This project may include logic flaws, bugs, or security issues. You can DM `fahisxd` on Discord to report problems.
