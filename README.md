# techtut-auth0

A runnable Spring Boot project that accompanies the TechTutorials article **"Spring Boot and Auth0: Login, Logout, Roles and Step-Up MFA"**.

It shows how to:

- Sign users in with **Auth0** using standard OpenID Connect (`spring-boot-starter-oauth2-client`, with no vendor SDK)
- Log out of both the app **and** Auth0 (OIDC RP-initiated logout)
- Map **Auth0 RBAC roles** to Spring Security `ROLE_*` authorities
- Require **step-up MFA** on sensitive pages: users are asked for a second factor only when they open those pages and haven't completed MFA in the last few minutes
- Apply the same step-up rule to a **REST API**, returning the [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) `insufficient_user_authentication` challenge

Built with Java 21, Spring Boot 3.5 and Spring Security 6.5.

## How step-up works

1. A signed-in user opens `/account/security` or `/payments`.
2. `StepUpAuthorizationManager` checks the ID token. `amr` must contain `mfa`, and `iat` must fall within `app.step-up.max-age`.
3. If not, `StepUpAccessDeniedHandler` saves the request and redirects to `/oauth2/authorization/auth0?step_up=true`.
4. `StepUpAuthorizationRequestResolver` adds `acr_values=http://schemas.openid.net/pape/policies/2007/06/multi-factor` to the Auth0 `/authorize` URL.
5. The `step-up-mfa` Auth0 Action sees `acr_values` and requires MFA.
6. Auth0 returns a new ID token with `"amr": ["mfa"]`, and the user lands back on the page they asked for.

Users who are denied for another reason, such as lacking the `admin` role, get a normal 403. They aren't sent through MFA.

## Project layout

| Path | Purpose |
|---|---|
| `src/main/java/.../SecurityConfig.java` | Browser security: OIDC login and logout, role mapping, step-up rules |
| `src/main/java/.../StepUpAuthorizationRequestResolver.java` | Adds `acr_values` to step-up logins |
| `src/main/java/.../StepUpAuthorizationManager.java` | Checks `amr` contains `mfa` and that the token is recent |
| `src/main/java/.../StepUpAccessDeniedHandler.java` | Saves the request and redirects to step-up (step-up paths only) |
| `src/main/java/.../ApiSecurityConfig.java` | `/api/**` resource server with RFC 9470 step-up challenge |
| `src/main/java/.../PageController.java`, `TransferController.java` | Demo pages and API |
| `auth0/actions/*.js` | Auth0 Actions to paste into your tenant |
| `src/test/java/...` | MockMvc tests for every branch; no Auth0 tenant needed |

## Pages

| URL | Requires |
|---|---|
| `/` | Nothing |
| `/profile` | Login. Shows your ID token claims, including `amr` and `iat`. |
| `/account/security` (GET and POST) | Login and recent MFA |
| `/payments` | Login and recent MFA |
| `/admin` | Login and the `admin` role |
| `GET /api/me` | Bearer access token |
| `POST /api/transfers` | Bearer access token with `mfa` in `https://example.com/amr` |

## Auth0 setup

### 1. Create the application

1. **Applications → Applications → Create Application → Regular Web Applications.**
2. On the **Settings** tab, note the **Domain**, **Client ID** and **Client Secret**.
3. **Allowed Callback URLs:** `http://localhost:8080/login/oauth2/code/auth0`
4. **Allowed Logout URLs:** `http://localhost:8080/`
5. Save. Under **Settings → Advanced** for the tenant, make sure **RP-Initiated Logout End Session Endpoint Discovery** is enabled (it's on by default for new tenants).

### 2. Enable MFA, controlled by an Action

1. **Security → Multi-factor Auth:** enable at least one factor. WebAuthn (security keys or device biometrics) resists phishing; one-time passwords and Guardian push are also supported.
2. Set **Require Multi-factor Auth** to **Never**. The Action below decides when MFA is needed.

### 3. Add the Actions

For each file in [`auth0/actions`](auth0/actions), go to **Actions → Library → Create Action → Build from scratch**, choose the **Login / Post Login** trigger, paste the code and **Deploy**. Then add the Actions to **Actions → Triggers → post-login**.

| Action | Needed for |
|---|---|
| [`step-up-mfa.js`](auth0/actions/step-up-mfa.js) | Step-up MFA (required) |
| [`add-roles.js`](auth0/actions/add-roles.js) | The `admin` role and the `/admin` page |
| [`add-amr-to-access-token.js`](auth0/actions/add-amr-to-access-token.js) | API step-up on `/api/transfers` |

### 4. Optional: roles and API

- **Roles:** under **User Management → Roles**, create a role called `admin` and assign it to your user.
- **API:** under **Applications → APIs → Create API**, use the identifier `https://techtut-auth0-api` (or set `AUTH0_AUDIENCE` to your own). Request an access token for this audience from a SPA or with the Auth0 test tools to call `/api/**`.

## Run locally

Requires Java 21. The Maven wrapper downloads Maven for you.

```bash
cp .env.example .env          # then fill in your Auth0 values
set -a; source .env; set +a
./mvnw spring-boot:run
```

Open http://localhost:8080, then:

1. Click **Log in**, sign in, and open **Profile**. `amr` won't include `mfa` yet.
2. Open **Security settings**. You'll be sent back to Auth0 for a second factor, and enrolled in one if you don't have one yet. Afterwards you land on the Security settings page.
3. Go back to **Profile**. `amr` now includes `mfa` and `iat` is recent.
4. To see re-verification, set `STEP_UP_MAX_AGE=1m`, wait a minute, and open **Security settings** again.

The app reads Auth0's discovery document at startup, so `AUTH0_DOMAIN` must point to a reachable tenant.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AUTH0_DOMAIN` | — | Your tenant domain, e.g. `your-tenant.eu.auth0.com` |
| `AUTH0_CLIENT_ID` | — | Application client ID |
| `AUTH0_CLIENT_SECRET` | — | Application client secret. Keep it out of source control. |
| `AUTH0_AUDIENCE` | `https://techtut-auth0-api` | Identifier of the Auth0 API for `/api/**` |
| `STEP_UP_MAX_AGE` | `10m` | How recently MFA must have been completed |
| `PORT` | `8080` | HTTP port |

## Tests

```bash
./mvnw test
```

The tests use Spring Security's `oidcLogin()` and `jwt()` support with explicit test endpoints (`src/test/resources/application.yml`), so they need no Auth0 tenant or network access. They cover:

- the step-up redirect and saved request
- the MFA freshness window
- `acr_values` added only for step-up
- a step-up protected POST
- a missing role giving a 403 rather than a step-up
- role mapping
- the API's RFC 9470 challenge

GitHub Actions runs them on every push and pull request.

## Deploying

- Serve the app over **HTTPS**, and add the production callback and logout URLs in Auth0.
- `server.forward-headers-strategy=framework` is already set, so redirect URIs use `https://` behind a proxy or load balancer.
- Provide the environment variables through your platform's secret store.

## Notes

- Spring Security 6.5 deprecates `AuthorizationManager.check` in favour of `authorize`, but `check` is still the abstract method to implement in 6.x, which is why the build shows one deprecation warning. On Spring Boot 4 / Spring Security 7, implement `authorize` instead.
- The custom claim namespace `https://example.com` is used in both the Actions and the Java code (`SecurityConfig.ROLES_CLAIM`, `ApiSecurityConfig.AMR_CLAIM`). If you change it, change it in both places.
