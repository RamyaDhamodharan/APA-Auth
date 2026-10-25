# AP Auth Service

FastAPI starter for authentication, refresh sessions, RBAC and admin user management, following the GenWorx AP Assistant LLD.

## Windows local run
1. Install Python 3.11+ and `uv`.
2. In this folder: `uv sync --extra dev`
3. Copy `.env.example` to `.env` and configure `DATABASE_URL` for the shared local PostgreSQL database.
4. Run: `uv run uvicorn src.main:app --reload --port 8001`
5. Open `http://127.0.0.1:8001/docs` or `http://127.0.0.1:8001/health`.

Access tokens are short-lived and returned to the frontend for in-memory use only. Refresh tokens are opaque, stored server-side as SHA-256 hashes, and delivered only in a Secure, HttpOnly cookie. By default the refresh cookie is a browser-session cookie; its server-side session still expires after `REFRESH_TOKEN_EXPIRE_DAYS`. Set `AUTH_PERSISTENT_SESSION=true` to restore a persistent cookie with the configured Max-Age. Configure `CORS_ALLOWED_ORIGINS` for the exact browser origins. The cookie is host-only by default, scoped to `/api/auth`, and uses `SameSite=Lax`; set `REFRESH_COOKIE_SAMESITE=none` only for an HTTPS deployment where the frontend and Auth are cross-site. Set `REFRESH_COOKIE_DOMAIN` only when deliberately sharing the cookie across trusted subdomains. Secure cookies are always enabled.

Apply Auth migrations with `uv run alembic upgrade head`. Migrations `0003` and `0004` are additive and check existing `auth.users` columns before adding the temporary-password and account-state fields. The live database must be reachable with the configured `DATABASE_URL` before applying them.

Public self-registration is disabled. `POST /admin/associates`, `GET /admin/associates`, `DELETE /admin/associates/{id}`, and `POST /admin/associates/{id}/reset-password` require an admin token. When omitted on create/reset, a cryptographically random temporary password is returned once. Its lifetime defaults to 24 hours (`TEMP_PASSWORD_TTL_HOURS`). The password is stored only as an Argon2 hash. A first-login token is limited to password change; `POST /auth/set-password` replaces the hash and clears the temporary-password flag and expiry. Other protected Auth and AP-Core routes reject limited tokens. Expired temporary passwords return 401 and require an admin reset.

## Create first admin

Configure `ADMIN_EMAIL` and `ADMIN_PASSWORD` in the root `.env`, then run
`docker compose exec auth python scripts/seed_admin.py`. The seed is idempotent:
it creates the admin if absent and skips without changing an existing account.
It never prints or stores the plaintext password. The interactive
`create_admin.py` utility remains available for manual promotion/reset workflows.
