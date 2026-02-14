# Product Strategy and Architecture Blueprint

## 1. Product vision

Build the leading US wrestling platform across K-6, middle school, high school, and college by combining:

- Competition operations (events, registration, brackets, results)
- Athlete development intelligence (historical stats and rankings)
- Communication and fan experience (real-time notifications and streaming)

## 2. Required capability map

### Identity and profiles

- User registration with role support: athlete, coach, parent/fan, admins
- Athlete profile with level/grade/weight and location metadata
- Coach profile with flexible associations:
  - Coach -> wrestler
  - Coach -> team/club
  - Coach -> wrestler + team/club

### Events and competition

- Tournament creation by coach, school, or club
- Divisions by level and weight class
- Search and discovery by state, city, date, fee, and level
- Grouping by state -> city

### Registration and payments

- Team-based registration
- Free-agent registration for team pickup workflows
- Entry fee checkout and payment confirmation path

### Brackets and match ops

- Manual bracket support
- Auto bracket generation modes:
  - Random
  - Seeded by ranking/history
- Match lifecycle:
  - Assigned mat
  - In-the-hole
  - Completed with result method/score

### Rankings and history

- Historical stats snapshots per athlete
- State + level ranking snapshots
- Always-available past results and rankings

### Notifications

- Subscription by event type/channel and optional event/athlete scope
- Channels:
  - SMS
  - Email
  - Both (two subscriptions)

### Streaming

- Stream session provisioning for mat-side devices
- Match-linked and event-linked streams
- Lifecycle state tracking for live/ended

## 3. Competitive baseline and differentiation

Reference rivals provided:

- https://arena.flowrestling.org/
- https://www.flowrestling.org/

Baseline expectations from this market include event discovery, registration, brackets, rankings, and live/replay viewing. Differentiators in this architecture:

- Native free-agent team matching workflow
- Notification subscriptions scoped to event + athlete + event type
- Unified historical stats and seeded bracket/ranking model
- API-first foundation for faster mobile and partner ecosystem growth

## 4. Technical architecture (state-of-the-art, pragmatic)

### Current implementation style

- Modular .NET backend split by concern (`Domain`, `Application`, `Infrastructure`, `Api`)
- REST API with OpenAPI support
- EF Core persistence
- SQLite for low-friction local development

### Production target architecture

- Frontend:
  - Web app (responsive) for athletes/coaches/parents/admins
  - Mobile app for notifications, match tracking, and stream viewing
- Backend:
  - Start as modular monolith for speed and low cost
  - Split into services when throughput justifies it:
    - Identity/Profile
    - Events/Registration
    - Brackets/Match Engine
    - Rankings/Stats
    - Notifications
    - Streaming control plane
- Data:
  - Managed PostgreSQL as source of truth
  - Redis for hot caching and notification fan-out
  - Object storage for VOD and media metadata
- Async/eventing:
  - Domain events for mat assignment, in-the-hole, results, and ranking updates

## 5. Security and reliability standards

- Hash passwords (current scaffold does SHA-256; move to Argon2 or PBKDF2 with per-user salts)
- Role-based authorization and policy enforcement per endpoint
- Signed webhooks for payment and streaming providers
- Audit logs for event edits, bracket edits, and result overrides
- Idempotency keys for registration and payment operations
- Rate limiting and abuse controls on public endpoints

## 6. Low-cost US launch strategy

### Phase A (MVP launch)

- Single API service + managed Postgres
- Managed notification providers (SMS/email)
- Managed streaming ingest/playback (pay-as-you-grow)
- Free subscription tier for all users

### Phase B (growth)

- Add Redis cache and background workers
- Introduce read replicas/search index for heavy tournament queries
- Add subscription billing and premium analytics tiers

## 7. Suggested product roadmap

1. Build responsive web UI (athlete/coach/admin personas)
2. Add authentication + authorization hardening
3. Integrate real payment provider (Stripe) and webhook reconciliation
4. Integrate real notification providers and delivery tracking
5. Add full bracket advancement logic (beyond first-round generation)
6. Add mobile apps for live match alerts and stream viewing
7. Launch paid subscription and enterprise tools for schools/clubs
