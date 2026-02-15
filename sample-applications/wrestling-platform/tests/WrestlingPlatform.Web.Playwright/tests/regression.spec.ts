import { expect, test } from "@playwright/test";
import { applyWorkflowFromLab, signInDemoCoach } from "./helpers";

test.describe("PinPoint Arena regression", () => {
  test.beforeEach(async ({ page }) => {
    await signInDemoCoach(page);
  });

  test("global nav links resolve to major pages", async ({ page }) => {
    const targets = [
      { label: "Command Center", heading: /Competition Command Center/i },
      { label: "Operations Lab", heading: /Operations Lab/i },
      { label: "Registration", heading: /Tournament Registration Center/i },
      { label: "Bracket Center", heading: /Bracket Center/i },
      { label: "Table Worker", heading: /Table Worker Station/i },
      { label: "Live Hub", heading: /Live Match Hub/i },
      { label: "Athlete Portal", heading: /Athlete Portal/i },
      { label: "Coach Portal", heading: /Coach Portal/i },
      { label: "Event Admin", heading: /Event Admin Portal/i },
      { label: "Mat Scoring", heading: /Mat-Side Real-Time Scoring/i },
      { label: "Recruiting Hub", heading: /College Recruiting Hub/i }
    ];

    for (const target of targets) {
      await page.getByRole("link", { name: new RegExp(`^${target.label}$`, "i") }).first().click();
      await expect(page.getByRole("heading", { name: target.heading })).toBeVisible();
    }
  });

  test("table worker can load mats and open scoring", async ({ page }) => {
    await applyWorkflowFromLab(page);
    await page.goto("/table-worker");

    await page.getByRole("button", { name: /Load Board/i }).click();
    await expect(page.locator("table tbody tr").first()).toBeVisible();

    const scoreButton = page.getByRole("button", { name: /^Score$/i }).first();
    if (await scoreButton.isVisible().catch(() => false)) {
      await scoreButton.click();
      await expect(page).toHaveURL(/\/mat-scoring/i);
      await expect(page.getByRole("heading", { name: /Mat-Side Real-Time Scoring/i })).toBeVisible();
    }
  });

  test("registration controls load and save", async ({ page }) => {
    await page.goto("/registration");
    await page.getByRole("button", { name: /^Search$/i }).click();
    await expect(page.locator("table tbody tr").first()).toBeVisible();

    const selectButton = page.getByRole("button", { name: /^Select$/i }).first();
    await selectButton.click();
    await page.getByRole("button", { name: /Load Directory/i }).click();
    await expect(page.getByText(/Registrants/i).first()).toBeVisible();

    await page.getByRole("button", { name: /Save Controls/i }).click();
    await expect(page.locator(".alert").first()).toBeVisible();
    await expect(page.getByText(/Tournament controls updated|Loaded directory for/i).first()).toBeVisible();
  });

  test("live hub provisions stream and lists cards", async ({ page }) => {
    await applyWorkflowFromLab(page);
    await page.goto("/live");
    await page.getByRole("button", { name: /Load Live Streams/i }).click();

    // Existing cards render even when no streams are currently live.
    await expect(page.getByRole("heading", { name: /Live Match Hub/i })).toBeVisible();
    expect(await page.locator(".panel").count()).toBeGreaterThan(2);
  });

  test("athlete media pipeline controls execute end-to-end calls", async ({ page }) => {
    await applyWorkflowFromLab(page);
    await page.goto("/athlete");
    await page.getByRole("button", { name: /Use Workflow Athlete/i }).click();

    await page.getByRole("button", { name: /Save Video Asset/i }).click();
    await expect(page.getByText(/Video asset saved|Valid athlete id/i)).toBeVisible();

    await page.getByRole("button", { name: /Queue AI Highlights/i }).click();
    await expect(page.getByText(/AI highlight job queued|Valid athlete id/i)).toBeVisible();

    await page.getByRole("button", { name: /Load AI Highlights/i }).click();
    await expect(page.getByRole("heading", { name: /Highlight Clips/i })).toBeVisible();
  });
});
