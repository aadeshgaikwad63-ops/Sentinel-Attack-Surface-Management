# SentinelASM

**AI Powered Attack Surface Management Platform**

> This repository module implements the **Backend Foundation** only:
> authentication, RBAC, user profiles, session management, and the base
> REST Authentication API. Vulnerability scanning, port/subdomain
> scanning, AI analysis, dashboard, reports, and attack surface discovery
> are owned by other teams/modules and are intentionally **not**
> implemented here.

---

## 1. Architecture

SentinelASM's backend uses the **Flask Application Factory** pattern with
**Blueprints** to keep feature areas isolated and independently
extensible by multiple developers.

```
SentinelASM/
├── app/
│   ├── __init__.py          # Application factory (create_app)
│   ├── extensions.py        # Shared extension instances (db, login, csrf, ...)
│   ├── auth/                 # Authentication blueprint (pages + REST API)
│   │   ├── __init__.py
│   │   ├── routes.py         # Register / Login / Logout / Password reset (HTML)
│   │   ├── api.py            # /api/auth/* JSON REST endpoints
│   │   └── forms.py          # WTForms
│   ├── models/                # SQLAlchemy models
│   │   ├── user.py
│   │   ├── role.py
│   │   ├── log.py
│   │   ├── setting.py
│   │   └── api_token.py
│   ├── api/                   # Foundation-level API namespace (/api/health, /api/version)
│   ├── profile/                # Authenticated user profile blueprint
│   ├── errors/                 # Centralized HTTP error handlers
│   ├── templates/
│   │   ├── base.html
│   │   ├── auth/               # Auth page templates
│   │   ├── profile/            # Profile page templates
│   │   └── errors/             # Error page templates
│   └── utils/                  # Decorators, validators, logging, email helper
├── instance/                    # Instance-specific files (SQLite DB, etc.) - not versioned
├── migrations/                  # Flask-Migrate/Alembic migration scripts
├── logs/                        # Rotating application log files
├── config.py                    # Environment-specific configuration classes
├── app.py                       # WSGI/CLI entry point
├── requirements.txt
├── .env.example
└── README.md
```

### Design principles for contributors

- **Application Factory** (`create_app`) — no module-level app instance,
  enabling multiple configurations (dev/test/prod) and clean testing.
- **Blueprints** — every feature area is a self-contained blueprint.
  New feature teams (scanners, AI, dashboard, reports) should add their
  **own** blueprint packages and register them in `app/__init__.py`
  alongside the existing ones — never modify `auth`, `profile`, `errors`,
  or `models` created by this foundation without coordination.
- **Extend, don't overwrite** — if a model or module already exists,
  extend it (e.g. new columns via a migration, new methods) rather than
  replacing the file.

---

## 2. Tech Stack

| Concern              | Library                     |
|-----------------------|------------------------------|
| Web framework          | Flask                        |
| ORM / Migrations       | Flask-SQLAlchemy, Flask-Migrate |
| Auth / Sessions         | Flask-Login                  |
| Forms / CSRF            | Flask-WTF, WTForms           |
| Rate limiting            | Flask-Limiter                |
| Config                   | python-dotenv                |
| Database (dev)            | SQLite                       |
| Database (prod)            | PostgreSQL (psycopg2-binary) |
| WSGI server (prod)          | Gunicorn                     |

---

## 3. Getting Started

### 3.1 Clone & create a virtual environment

```bash
python3.13 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3.2 Configure environment variables

```bash
cp .env.example .env
# Edit .env and set a strong SECRET_KEY, database URL, etc.
```

### 3.3 Initialize the database

```bash
export FLASK_APP=app.py            # Windows (PowerShell): $env:FLASK_APP="app.py"
flask db init                        # only once, first time in the repo
flask db migrate -m "Initial schema"
flask db upgrade
```

### 3.4 Seed default roles and create an admin user

```bash
flask seed-roles
flask create-admin
```

### 3.5 Run the development server

```bash
flask run
# or
python app.py
```

The app will be available at `http://127.0.0.1:5000`.

### 3.6 Run in production (Gunicorn)

```bash
export FLASK_ENV=production
gunicorn "app:create_app()" --workers 4 --bind 0.0.0.0:8000
```

> **Note:** the top-level `app.py` file and the `app/` package share the
> name `app`, and Python's import system always resolves a bare `import
> app` to the *package* (`app/__init__.py`), not the script. Gunicorn's
> factory-call syntax (`app:create_app()`) sidesteps this by calling the
> application factory in `app/__init__.py` directly, and is the
> recommended production entry point. `flask run` and `python app.py`
> are unaffected and work as expected for local development, since they
> load `app.py` by file path rather than by package import.

---

## 4. Authentication

### 4.1 Browser (session-based) pages

| Route                              | Method   | Description                     |
|--------------------------------------|----------|----------------------------------|
| `/auth/register`                      | GET/POST | Create a new account (role: viewer) |
| `/auth/login`                          | GET/POST | Log in, optional "remember me"   |
| `/auth/logout`                          | GET      | Log out the current session      |
| `/auth/forgot-password`                  | GET/POST | Request a password reset email   |
| `/auth/reset-password/<token>`            | GET/POST | Set a new password via signed token |

### 4.2 REST Authentication API (JSON, Bearer token)

| Route                    | Method | Auth          | Description                          |
|----------------------------|--------|----------------|----------------------------------------|
| `/api/auth/register`        | POST   | None            | Create a new account                    |
| `/api/auth/login`             | POST   | None            | Verify credentials, issue an API token   |
| `/api/auth/logout`             | POST   | Bearer token     | Revoke the presented API token           |
| `/api/auth/me`                   | GET    | Bearer token     | Return the authenticated user's profile  |

Example login request:

```bash
curl -X POST http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identity": "jane_doe", "password": "S3curePass"}'
```

Example authenticated request:

```bash
curl http://127.0.0.1:5000/api/auth/me \
  -H "Authorization: Bearer sasm_xxxxxxxxxxxxxxxx"
```

### 4.3 User Profile

| Route                             | Method   | Description                          |
|--------------------------------------|----------|----------------------------------------|
| `/profile/`                            | GET      | View current user profile & tokens      |
| `/profile/edit`                          | GET/POST | Edit profile fields                     |
| `/profile/change-password`                | GET/POST | Change account password                 |
| `/profile/tokens/create`                    | POST     | Generate a new personal API token        |
| `/profile/tokens/<id>/revoke`                 | POST     | Revoke a personal API token              |

### 4.4 Foundation API

| Route            | Method | Description         |
|--------------------|--------|-----------------------|
| `/api/health`         | GET    | Liveness/readiness probe |
| `/api/version`          | GET    | Application version info |

---

## 5. Role Based Access Control (RBAC)

Three default roles are seeded via `flask seed-roles`:

- **admin** — full administrative access.
- **analyst** — operates scanning/analysis features (owned by other modules).
- **viewer** — read-only access; default role for new registrations.

Restrict a view to specific roles:

```python
from app.utils.decorators import roles_required

@roles_required("admin", "analyst")
def some_view():
    ...
```

Restrict a REST API view to a valid Bearer token:

```python
from app.utils.decorators import api_token_required

@api_token_required
def some_api_view():
    ...
```

---

## 6. Database Tables

| Table          | Purpose                                              |
|------------------|--------------------------------------------------------|
| `users`            | Account credentials, profile fields, RBAC role link       |
| `roles`             | RBAC role definitions (admin/analyst/viewer)               |
| `logs`               | Audit trail of security/system events                       |
| `settings`            | Global key/value application settings                        |
| `api_tokens`            | Hashed personal access tokens for the REST API                |

---

## 7. Security Notes

- Passwords are hashed with Werkzeug's `generate_password_hash`
  (PBKDF2/scrypt depending on Werkzeug version) — never stored in plaintext.
- CSRF protection is enabled globally via Flask-WTF for all
  session/cookie-based form routes. Stateless JSON API blueprints
  (`/api/auth/*`, `/api/*`) are explicitly exempted since they authenticate
  via Bearer tokens, not cookies.
- Session and "remember me" cookies are configured `HttpOnly`,
  `SameSite=Lax`, and `Secure` in production.
- Authentication routes (`register`, `login`, `forgot-password`,
  `reset-password`) are rate-limited via Flask-Limiter to mitigate
  brute-force and enumeration attacks.
- Password reset tokens are signed and time-limited using `itsdangerous`
  and are single-purpose (salted separately from other token types).
- API tokens are stored as SHA-256 hashes only; the plaintext token is
  shown to the user exactly once at creation time.
- All user input is validated both at the form layer (WTForms validators)
  and the API layer (`app/utils/validators.py`) to keep validation rules
  consistent across entry points.

---

## 8. Logging

- Application logs are written to both the console and a rotating file
  handler at `logs/sentinelasm.log` (5 MB per file, 5 backups retained).
- Security-relevant events (login success/failure, registrations,
  password resets, token creation/revocation, RBAC denials) are
  additionally persisted to the `logs` database table via
  `app.utils.logging.log_action()` for auditability.

---

## 9. Testing Configuration

A `TestingConfig` is provided (in-memory SQLite, CSRF disabled, rate
limiting disabled) for use with `pytest` + `Flask-Testing` or a custom
test client fixture:

```python
from app import create_app
from app.extensions import db

app = create_app("testing")
with app.app_context():
    db.create_all()
```

---

## 10. Contribution Guidelines (Multi-Developer Project)

- This module owns: `app/auth`, `app/profile`, `app/errors`,
  `app/models`, `app/utils`, `app/extensions.py`, `config.py`, `app.py`.
- Do **not** implement Vulnerability Scanner, Port Scanner, Subdomain
  Scanner, AI, Dashboard, Reports, or Attack Surface Discovery in this
  module — those belong to dedicated feature blueprints.
- Register new feature blueprints in `app/__init__.py` following the
  existing `_register_blueprints()` pattern; do not remove or reorder
  the blueprints already registered there.
- If you need new user-facing fields or tables, extend the existing
  models/migrations — do not create parallel/duplicate tables.
