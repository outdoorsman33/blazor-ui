# Playwright Regression Suite

Run after local API and web services are up:

```powershell
cd tests/WrestlingPlatform.Web.Playwright
npm install
npx playwright install --with-deps
npm test
```

Optional base URL override:

```powershell
$env:PLAYWRIGHT_BASE_URL="http://127.0.0.1:5105"
npm test
```

The suite covers:

- cross-page navigation health
- table-worker to mat-scoring workflow handoff
- tournament registration controls and bracket directory load
- live hub rendering and stream board checks
- athlete media vault + AI job queue controls
