# crm-backend

Backend for a multi-tenant CRM for Romanian companies. Java 25, Spring Boot 4, PostgreSQL.

What it does today:

- **Signup**: creates a company (tenant) and its first user, who is the company's admin.
- **Login, refresh and logout**.
- **`GET /api/me`**: who is logged in.
- **Contacts**: create, read, update and delete (`/api/contacts`). Only admins can delete.

## Run it locally

You need Docker Desktop and Java 25.

1. Create your local secrets file. It is never committed.

   ```powershell
   Copy-Item .env.example .env
   ```

   Then replace every `change-me` in `.env` with a random value. This prints one (use it for `CRM_JWT_SECRET` too):

   ```powershell
   $b = New-Object byte[] 48; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b)
   ```

2. Start the database:

   ```powershell
   docker compose up -d --wait
   ```

3. Start the app on http://localhost:8080:

   ```powershell
   .\mvnw.cmd spring-boot:run
   ```

4. Run the tests. They start their own PostgreSQL in Docker:

   ```powershell
   .\mvnw.cmd test
   ```

## API

| Method | Path | Who | What |
|---|---|---|---|
| POST | `/api/auth/signup` | anyone | `{companyName, cui?, fullName, email, password}` → access token + refresh cookie |
| POST | `/api/auth/login` | anyone | `{email, password}` → access token + refresh cookie |
| POST | `/api/auth/refresh` | refresh cookie | new access token + new refresh cookie |
| POST | `/api/auth/logout` | refresh cookie | ends the session |
| GET | `/api/me` | logged in | current user and company |
| GET | `/api/contacts?page=0&size=20` | logged in | contacts of your company |
| GET | `/api/contacts/{id}` | logged in | one contact |
| POST | `/api/contacts` | logged in | create |
| PUT | `/api/contacts/{id}` | logged in | update |
| DELETE | `/api/contacts/{id}` | admin | delete |
| GET | `/actuator/health` | anyone | health check |

Send the access token as `Authorization: Bearer <token>`. It expires after 15 minutes; then call `/api/auth/refresh`.

## Security design

### Companies can't see each other's data

Every company is a tenant. Every table has a `tenant_id` column, and PostgreSQL **Row-Level Security (RLS)** filters every query to the current tenant inside the database itself. The code never adds `WHERE tenant_id = ...`, so a forgotten filter cannot leak data.

- **Where the tenant comes from.** Only from the signed access token (the `tid` claim), never from the request. `TenantAwareDataSource` sets it on each database connection. If no tenant is set, the database returns no rows at all.
- **Two database roles.**
  - `crm_owner` owns the schema and runs the migrations.
  - `crm_app` is what the running app uses. It cannot bypass RLS or change the schema.
- **Startup guard.** `TenantIsolationGuard` stops the app from starting if:
  - the app's database user is a superuser, can bypass RLS, or owns tables;
  - any table has RLS switched off.
- **Lookups before login.** Login and token refresh need to find a user or token before the tenant is known. They do it through two narrow `SECURITY DEFINER` functions, not through open access to the tables.

### Accounts and sessions

- **Passwords.** Hashed with PBKDF2-HMAC-SHA256. The hash records which algorithm made it, so the algorithm can be upgraded later; old hashes are re-hashed at the next login. Passwords must be 12–128 characters.
- **Access token.** A JWT signed with HS256 that lives 15 minutes. The frontend should keep it in memory only. The server accepts only HS256 tokens with the right issuer that carry a tenant and a user.
- **Refresh token.**
  - Random, stored only as a SHA-256 hash.
  - Sent as a cookie with `HttpOnly; Secure; SameSite=Strict; Path=/api/auth`, so JavaScript can't read it.
  - Works once (rotation). If an old one is used again, all of that user's sessions end.
- **Login protection.**
  - A wrong password and an unknown e-mail give the same answer and take the same time.
  - After 5 failed logins per account, or 30 per IP address, logins are blocked for 15 minutes.
  - Signups are limited per IP address.

### Web

- **Protected by default.** Every endpoint needs a token unless it is explicitly listed as public, so new endpoints start protected.
- **Strict CORS.** Only the addresses in `CRM_CORS_ALLOWED_ORIGINS` may call the API from a browser.
- **Security headers.** CSP `default-src 'none'`, `X-Frame-Options: DENY`, HSTS, `no-store` caching, no referrer.
- **No internals in errors.** Errors are fixed messages in RFC 9457 format. They never include SQL, stack traces or exception names.
- **No mass assignment.** Request bodies have no id, tenant or role fields, so extra JSON properties are ignored.
- **Minimal actuator.** Only `/actuator/health` is public, without details.
- **Secrets only from the environment.** If a secret is missing, the app refuses to start.

### Tests that check all of this (`src/test`)

- **`TenantIsolationTest`**:
  - one company can't read, change or delete another company's contacts;
  - a `tenantId` sent in the request body is ignored;
  - the database returns nothing when no tenant is set;
  - the database rejects writing a row into another tenant;
  - only admins can delete.
- **`AuthSecurityTest`**:
  - forged and altered tokens are rejected;
  - the cookie flags are correct;
  - logins don't reveal whether an e-mail exists;
  - repeated failed logins are blocked;
  - refresh rotation and reuse detection work;
  - logout ends the session;
  - security headers are present and error responses contain no internals.
- **`TenantIsolationGuardTest`**: the app refuses to start when it connects as the table owner.

## Rules for new code

1. **Every new table** gets `tenant_id uuid NOT NULL DEFAULT current_tenant_id()`, `ENABLE ROW LEVEL SECURITY`, a `tenant_isolation` policy, and `GRANT`s to `${appRole}`. Copy `V2__contacts.sql`. The startup guard fails if RLS is missing. A table that really is shared between companies still needs RLS, with an explicit `USING (true)` policy.
2. **Request bodies** never contain `tenantId`, `role` or other fields the user must not control.
3. **Secrets** go in `.env` locally and in the hosting provider's secret settings in production, never in the code.

## Not done yet (next steps)

- E-mail verification at signup, password reset, and inviting users. These need an e-mail service.
- An audit log of important actions.
- The login rate limit is kept in memory. With more than one app server it must move to Redis.
- Accounts can be locked by someone guessing passwords on purpose; a CAPTCHA after a few failures would prevent that.
- Behind the production proxy (Caddy or a load balancer), set `server.forward-headers-strategy=native` so the rate limit sees the real client IP address.
- Production: create `crm_owner` and `crm_app` in Scaleway's managed PostgreSQL with the same rights as `docker/postgres/init/01-roles.sh`.
