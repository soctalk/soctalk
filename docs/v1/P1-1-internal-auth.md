# P1-1 — Internal authentication

## 1. Scope

Adds a self-contained login path for SocTalk's first-party UIs so
operators can run without an upstream OIDC proxy. Existing authz
(roles, `tenant_id`, decorators at `src/soctalk/core/tenancy/
decorators.py:120`, Postgres RLS) is unchanged. This spec only adds a
new identity source that produces the same `UserIdentity` shape already
consumed in `src/soctalk/core/tenancy/auth.py:67`.

Two modes, selected at process start and surfaced on `/healthz`:

```
SOCTALK_AUTH_MODE = internal | proxy
```

- `internal` (default for new installs) — SocTalk owns login, sessions,
  password storage. Ingress-handoff middleware is disabled.
- `proxy` — the V1 behaviour. Internal endpoints respond with 404.

No hybrid mode. Federation (JIT provisioning, OIDC SP, etc.) is a
separate spec.

## 2. Data model

Two new tables. Everything else reuses existing models.

### 2.1 `password_credentials`

| column               | type        | notes                                       |
| ---                  | ---         | ---                                         |
| user_id              | uuid PK, FK | references `users.id`, on-delete cascade    |
| password_hash        | text NOT NULL | argon2id, full hash string with parameters |
| must_change          | bool        | set by admin reset                          |
| updated_at           | timestamptz |                                             |
| last_used_at         | timestamptz | last successful login                       |
| consecutive_failures | int         | reset on success                            |
| locked_until         | timestamptz | null unless lockout active                  |

### 2.2 `sessions`

DB-backed sessions. Cookie carries an opaque session_id; DB row is the
source of truth.

| column          | type        | notes                                |
| ---             | ---         | ---                                  |
| id              | uuid PK     | also the cookie value                |
| user_id         | uuid FK     |                                      |
| tenant_context  | uuid        | `current_tenant` captured at login   |
| created_at      | timestamptz |                                      |
| last_seen_at    | timestamptz | updated throttled (~60s)             |
| absolute_expiry | timestamptz | hard cap, 12h                        |
| idle_expiry     | timestamptz | slides on activity, 30m              |
| revoked_at      | timestamptz | non-null disables the session        |
| ip_created      | inet        | observability                        |
| user_agent      | text        | observability                        |

Index: `(user_id, revoked_at)`.

### 2.3 Reuse

- `users` (`src/soctalk/core/tenancy/models.py:156`) — unchanged.
- `audit_log` (`src/soctalk/core/tenancy/models.py:291`) — receives
  `auth.*` actions (see §9).

No new audit table. No signing-key table (sessions are opaque DB rows,
not JWTs; the existing HMAC signing at
`src/soctalk/core/tenancy/auth.py:167` is unrelated).

## 3. Endpoints

All under `/api/auth/*`. JSON. State-changing routes protected per §6.

| method | path                                          | purpose                                |
| ---    | ---                                           | ---                                    |
| POST   | `/api/auth/login`                             | email + password, sets session cookie  |
| POST   | `/api/auth/logout`                            | revokes current session                |
| GET    | `/api/auth/me`                                | returns current identity payload       |
| POST   | `/api/auth/password/change`                   | old + new, authenticated               |
| POST   | `/api/mssp/users/{id}/password/reset`         | admin forced reset, sets `must_change` |

The admin-reset endpoint generates a strong random password server-side
and returns it once in the response body; the admin hands it to the
user out-of-band. Self-service email-based reset is deferred (§12).

In `AUTH_MODE=proxy`, every endpoint in this table responds with 404.

## 4. Cookie and session

### 4.1 Cookie

Name: `soctalk_session`.

Attributes:

- `HttpOnly`
- `Secure`
- `SameSite=Lax`
- `Path=/`
- `Domain` omitted (host-only)
- `Max-Age` matches session `absolute_expiry`

Value: url-safe base64 of the session UUID. No claims in the cookie.

### 4.2 Lifecycle

- `absolute_expiry = created_at + 12h`. Hard cap.
- `idle_expiry = last_seen_at + 30m`. Slides forward on activity.
- On password change: all other sessions for the user are revoked; the
  session that made the change is preserved so the user stays logged in
  on their current device.
- `/api/auth/logout` revokes only the current session.
- Admin reset revokes all sessions for the target user.

## 5. Password policy

- argon2id via `argon2-cffi`.
- Parameters: `time_cost=3`, `memory_cost=65536` (64 MiB),
  `parallelism=4`, `hash_len=32`, `salt_len=16`.
- The stored hash string contains its parameters; verify-and-rehash
  transparently when parameters drift.
- Minimum length: 12. No composition rules.
- Lockout: 10 consecutive failures within 15 min → `locked_until = now()
  + 15m`. Counter resets on successful login.
- `must_change`: set by admin reset. Forces the user through the
  change-password flow before any other endpoint.

## 6. CSRF

`SameSite=Lax` on the session cookie already blocks cross-site POST.
For state-changing methods (`POST`, `PATCH`, `DELETE`, `PUT`) the
middleware additionally enforces:

- If `Origin` is present, it must equal the configured first-party
  origin (`SOCTALK_PUBLIC_ORIGIN`).
- Else if `Referer` is present, its origin component must match.
- Else reject with 403.

This is sufficient for the first-party Svelte UIs. No double-submit
cookie needed.

## 7. Middleware

New middleware `internal_session_middleware` replaces
`ingress_handoff_middleware` when `SOCTALK_AUTH_MODE=internal`.

Per request:

1. Read the `soctalk_session` cookie.
2. Look up the session row. Reject if missing, revoked, past
   `absolute_expiry`, or past `idle_expiry`.
3. Update `last_seen_at` (throttled — write at most every 60s).
4. Load the user and construct the same `UserIdentity` shape produced
   by the V1 path. Set `request.state.user_identity` exactly as today,
   so decorators and RLS context helpers are untouched.

Rate limiting: login attempts per IP and per email per 15 minutes,
applied before DB lookup. In-process counter for beta; swap for Redis
when we need horizontal scale.

## 8. UI/UX

Two first-party UIs gain auth affordances: the MSSP console
(`frontend/mssp`) and the customer portal (`frontend/customer`). Both
are SvelteKit apps talking to the same API.

### 8.1 Login page

Both apps gain `/login`:

- Centered card. Two fields (Email, Password). Single primary button
  labelled "Sign in."
- Customer portal reads app name and logo from the tenant's
  `BrandingConfig` so the page feels native to the MSSP's brand. MSSP
  console uses the install-level default branding.
- Initial focus on Email. Enter submits. Standard field names so
  browser password managers autofill cleanly.
- Error states (no user enumeration):
  - Invalid credentials → "Email or password is incorrect."
  - Locked account → "This account is temporarily locked. Try again at
    {unlock_time}."
  - Server error → "Something went wrong. Try again."
- Small utility line underneath: "Contact your administrator if you've
  lost access." No self-service reset link in this spec.

### 8.2 Forced change (`must_change`)

When login succeeds against a credential with `must_change=true`, the
server response signals the change as the next step. The UI navigates
straight to `/account/password` — no dashboard flash.

While `must_change` is set, any route except `/account/password` and
`POST /api/auth/logout` redirects back to `/account/password`. A small
amber banner reads "Your administrator requires you to set a new
password before continuing."

### 8.3 Password change page

`/account/password`:

- Three fields: Current password, New password, Confirm new password.
- Inline validator for the ≥12 length rule only. No composition meter.
- On success, show a confirmation and the note "Other devices have
  been signed out. You're still signed in here."
- Reachable from the account menu, and mandatory during `must_change`.

### 8.4 Account menu

In the header of both apps, visible when authenticated:

- User email.
- Role label ("MSSP admin", "Analyst", "Customer viewer", etc.).
- Link to "Change password."
- "Sign out" — `POST /api/auth/logout`, then navigate to `/login` with
  a flash message "You have been signed out."

### 8.5 Admin reset (MSSP console)

On the user detail page in the MSSP console:

- "Reset password" button, permission-gated to `platform_admin` and
  `mssp_admin`.
- Confirmation modal explains: "Generates a one-time password, revokes
  all of this user's active sessions, and forces them to change it at
  next login."
- On confirm, the server returns the generated password once. The UI
  renders it in a copy-to-clipboard field with "Copy and close." After
  the modal closes, the password is no longer retrievable — the admin
  shares it out of band.

### 8.6 Session expiry

- On any 401 returned to an authenticated session, the SPA navigates to
  `/login?expired=1&next=<current-url>`.
- The login page reads `expired=1` and shows "Your session expired.
  Please sign in again." Absolute vs idle expiry is not distinguished
  in the UI.
- After successful sign-in, the SPA navigates to `next` if present and
  same-origin; otherwise to the default landing route for that UI.

### 8.7 Empty and error states

- First load with no session → redirect to `/login` (no flash).
- Login page while already authenticated → redirect to the default
  landing route (don't strand the user on a form they don't need).
- Network errors during login → keep the form, render inline "Couldn't
  reach the server. Check your connection and try again."

### 8.8 Accessibility

- All inputs have associated `<label>` elements. Errors use
  `role="alert"` so screen readers announce them.
- Focus order is natural (email → password → submit).
- No CAPTCHA. Lockout plus IP/email rate limiting cover abuse at MSSP
  scale; CAPTCHA breaks screen-reader flow and adds ops overhead.
- Minimum touch target 44×44px for the primary action on mobile.

## 9. Audit

Emit the following `action` values into the existing `audit_log`:

- `auth.login.success`
- `auth.login.failure` (`details.reason` in `{bad_password, unknown_email, locked}`)
- `auth.logout`
- `auth.password.changed`
- `auth.password.reset.admin` (admin-triggered reset of another user)
- `auth.lockout.triggered`

`actor_id` is the acting user's id, or `system:auth` for lockout
triggers. `tenant_id` is copied from the acting user.

## 10. Migration from `proxy` to `internal`

1. Apply migration that creates §2.1 and §2.2. Existing `users` rows
   are unaffected.
2. Deploy the new app version. `SOCTALK_AUTH_MODE=proxy` preserves
   existing behaviour.
3. For each user expected to use internal login, the operator runs
   `soctalk auth set-password <email>` (new CLI; writes a
   `password_credentials` row and emits `auth.password.reset.admin`).
4. Operator flips `SOCTALK_AUTH_MODE=internal` and restarts. The
   ingress-handoff middleware is removed from the pipeline.

Rollback: flip the flag back and restart.

## 11. Tests

Mandatory backend suite (P0-4 §9 style):

1. Login happy path creates a session row with the right
   `tenant_context` and sets the cookie.
2. Wrong password increments `consecutive_failures`; ten consecutive
   triggers `locked_until`; further attempts reject even with the right
   password.
3. `must_change` blocks every non-password endpoint until a successful
   change.
4. Password change revokes all other sessions for the user but preserves
   the current one.
5. Logout revokes only the current session.
6. Admin reset revokes all sessions for the target user and forces
   `must_change`.
7. `AUTH_MODE=proxy`: `/api/auth/*` and the admin reset endpoint return
   404. Ingress-handoff path still works.
8. CSRF: state-changing request with a foreign `Origin` is rejected
   with 403.
9. Session past `absolute_expiry` or `idle_expiry` is rejected; row is
   not auto-deleted (retained for audit).

Playwright smoke suite for each UI:

1. Login with valid credentials lands on the default route and shows
   the account menu.
2. Login with bad credentials shows the generic error without enumerating.
3. `must_change` on login lands on the change page and cannot navigate
   elsewhere.
4. Password change succeeds and persists sign-in.
5. Admin reset modal surfaces the generated password once; closing the
   modal hides it.
6. Expired session on a protected route routes to `/login?expired=1`
   with the flash and preserves `next`.

## 12. Deferred

Not part of this spec. Ordered by likely add-back:

1. `password_reset_tokens` — self-service email-based password reset.
2. MFA (TOTP + recovery codes), with corresponding UI steps in the
   login and account flows.
3. Session inventory (`GET /api/auth/sessions`, revoke-specific,
   logout-all) with a "Devices" panel in the account page.
4. Impersonation (mssp_admin → tenant user sessions), with a clear
   banner in the UI while impersonating.
5. OIDC SP / federation (separate spec).
6. OIDC issuer (separate spec; only if a concrete consumer appears).
7. Signing-key rotation + JWKS (only needed once we issue stateless
   tokens externally).
