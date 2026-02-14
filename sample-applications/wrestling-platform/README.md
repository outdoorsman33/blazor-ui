# Wrestling Platform (US) MVP Foundation

This folder contains a production-oriented **API + web portal** baseline for a US wrestling platform designed to exceed Flo-style workflows.

## What is implemented now

- Multi-project .NET solution:
  - `WrestlingPlatform.Domain`
  - `WrestlingPlatform.Application`
  - `WrestlingPlatform.Infrastructure`
  - `WrestlingPlatform.Api`
  - `WrestlingPlatform.Web`
- Athlete/coach registration and profile creation
- Team/club creation and coach associations
- Tournament + division management
- Tournament discovery by state/city/date/level/fee
- Event registration (team or free-agent)
- Payment checkout intent + confirmation workflow
- Bracket generation (`Manual`, `Random`, `Seeded`) with round progression updates
- Match operations (mat assignment, in-the-hole, result recording)
- Historical stats and rankings
- Notification subscription + dispatch pipeline
- Stream session provisioning and live status control

## Security and auth

- JWT auth with role policies (`CoachOrAdmin`, `EventOps`)
- Access + refresh token model:
  - `POST /api/auth/login`
  - `POST /api/auth/refresh` (refresh-token rotation)
  - `POST /api/auth/logout` (revokes active refresh tokens)
  - `GET /api/auth/me`
- Refresh tokens are stored hashed and revocable
- Password hashing uses PBKDF2 (legacy SHA-256 hashes still validated)
- Public self-registration restricted to `Athlete`, `Coach`, `Parent`, `Fan`
- Ownership checks enforced for user/profile/athlete/notification/payment-sensitive endpoints

## Payment webhook and reconciliation

- Stripe-compatible webhook ingestion endpoints:
  - `POST /api/webhooks/stripe`
  - `POST /api/webhooks/stripe/payment-confirmed` (legacy-compatible path)
- Signature verification supports `Stripe-Signature` (with timestamp tolerance) and legacy header fallback (`X-Webhook-Secret`)
- Webhook events are persisted for idempotency/retry
- Background reconciliation worker processes pending webhook events asynchronously
- Manual processing endpoint for ops users:
  - `POST /api/payments/reconciliation/process?batchSize=50`

## Provider integration modes

Configurable in `src/WrestlingPlatform.Api/appsettings*.json`:

- Payments:
  - `ProviderMode = Mock` (default)
  - `ProviderMode = Stripe` (uses Stripe Checkout session API)
- Notifications:
  - `ProviderMode = Mock` (default)
  - `ProviderMode = Live` (Twilio SMS + SendGrid email)

## Web portal routes

- `/`: command center dashboard
- `/athlete`: athlete registration/profile/entry/stats/notifications
- `/coach`: coach profile/team/association/free-agent recruiting
- `/admin`: event/division/bracket/match/stream operations

The top header includes sign-in/sign-out controls, keeps session state in-memory, and transparently refreshes access tokens when they are near expiry.

## US level coverage

- `ElementaryK6`
- `MiddleSchool`
- `HighSchool`
- `College`

## Quick start

```bash
dotnet restore WrestlingPlatform.slnx
dotnet build WrestlingPlatform.slnx
```

Run API and web app (separate terminals):

```bash
dotnet run --project src/WrestlingPlatform.Api --urls http://127.0.0.1:5099
dotnet run --project src/WrestlingPlatform.Web --urls http://127.0.0.1:5105
```

Open:

- Web portal: `http://127.0.0.1:5105`
- OpenAPI: `http://127.0.0.1:5099/openapi/v1.json`

## Render Production Deployment

- Blueprint file: `../../render.yaml`
- Runbook: `docs/DEPLOYMENT-RENDER.md`

This blueprint provisions:
- `wrestling-platform-web` (public web)
- `wrestling-platform-api` (API)
- `wrestling-platform-db` (managed Postgres with HA)

Deploy by creating a Render Blueprint from your GitHub repo, then follow the runbook for secrets, domain, and monitoring setup.
## One-command Public Demo URL (Quick Tunnel)

From this folder:

```powershell
./scripts/start-public-demo.ps1
```

This starts API + Web + a Cloudflare quick tunnel and prints a public URL.

Stop everything:

```powershell
./scripts/stop-public-demo.ps1
```

## NuGet source stability

A local `NuGet.Config` is included in this folder to force `nuget.org` and avoid machine-level private feed failures.

## Rival references provided for benchmark

- https://arena.flowrestling.org/
- https://www.flowrestling.org/

See `docs/PRODUCT-STRATEGY.md` for broader roadmap and architecture strategy.

