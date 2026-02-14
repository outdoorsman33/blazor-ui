# Render Production Deployment Runbook

This runbook deploys the wrestling platform to Render with:
- `wrestling-platform-web` (public web app)
- `wrestling-platform-api` (public API service used by web)
- `wrestling-platform-db` (managed PostgreSQL with HA enabled)

## Files Used
- Blueprint: `render.yaml` (repo root)
- API image: `sample-applications/wrestling-platform/src/WrestlingPlatform.Api/Dockerfile`
- Web image: `sample-applications/wrestling-platform/src/WrestlingPlatform.Web/Dockerfile`

## Prerequisites
- GitHub repo connected to Render.
- Render workspace with support for autoscaling and HA Postgres (Professional tier recommended).
- A custom domain you control.

## Deploy Steps
1. Push this branch to GitHub.
2. In Render, select `New` -> `Blueprint`.
3. Select this repository and the target branch.
4. Confirm Render detects `render.yaml` at repo root.
5. Review services and database:
   - `wrestling-platform-web`
   - `wrestling-platform-api`
   - `wrestling-platform-db`
6. Fill secret env vars before first production launch:
   - `Payments__StripeSecretKey`
   - `Payments__StripeWebhookSecret`
   - `Notifications__Twilio__AccountSid`
   - `Notifications__Twilio__AuthToken`
   - `Notifications__Twilio__FromNumber`
   - `Notifications__SendGrid__ApiKey`
   - `Notifications__SendGrid__FromEmail`
   - Optional OTEL endpoint: `OTEL_EXPORTER_OTLP_ENDPOINT`
7. Start deploy.

## Post-Deploy Verification
1. Open web service URL from Render.
2. Verify health endpoints:
   - Web: `https://<web-service-domain>/healthz`
   - API: `https://<api-service-domain>/healthz`
3. Run smoke checks:
   - register user
   - login/logout
   - create athlete profile
   - search events

## Custom Domain
1. In Render, open `wrestling-platform-web` -> `Settings` -> `Custom Domains`.
2. Add your domain (for example `app.yourdomain.com`).
3. Create DNS records exactly as Render provides.
4. Wait for certificate issuance and verify HTTPS.

## Monitoring And Reliability
- Enable Render alerts on both web services:
  - high CPU
  - high memory
  - repeated deploy failures
  - unhealthy instance count
- Add external uptime checks (Pingdom/UptimeRobot/Better Stack) for:
  - `/healthz` on web and API
- Use Render logs and metrics dashboard for error spikes and latency.
- Keep `minInstances >= 2` for both API and web to avoid single-instance downtime.
- Keep Postgres HA enabled for automatic primary failover.

## Scaling Guidance
- Start with blueprint defaults (`standard` web services, `pro-4gb` HA Postgres).
- If p95 latency rises:
  - increase `maxInstances`
  - raise API plan first, then web plan
  - increase Postgres plan and add read replicas (if read-heavy)

## Rollback
- Render supports rollback to a previous deploy from each service's deploy history.
- Database recovery uses managed backups/PITR in Render Postgres.

## Notes
- The API uses EF Core `EnsureCreated` for schema bootstrap.
- For strict production change control, move to explicit EF migrations as the next hardening step.
