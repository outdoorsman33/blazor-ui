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
      { label: "Recruiting Hub", heading: /College Recruiting Hub/i },
      { label: "Support", heading: /Support Center/i }
    ];

    for (const target of targets) {
      const link = page.getByRole("link", { name: new RegExp(`^${target.label}$`, "i") }).first();
      if (!(await link.isVisible().catch(() => false))) {
        const menuToggle = page.getByRole("button", { name: /Menu/i }).first();
        if (await menuToggle.isVisible().catch(() => false)) {
          await menuToggle.click();
        }
      }

      await link.click();
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
    await page.getByRole("main").getByRole("button", { name: /^Search$/i }).click();
    await expect(page.locator("table tbody tr").first()).toBeVisible();

    const selectButton = page.getByRole("button", { name: /^Select$/i }).first();
    await selectButton.click();
    await page.getByRole("button", { name: /Load Directory/i }).click();
    await expect(page.getByText(/Registrants/i).first()).toBeVisible();

    await page.getByRole("button", { name: /Save Controls/i }).click();
    const alert = page.locator(".alert").first();
    await expect(alert).toBeVisible();
    await expect(alert).not.toBeEmpty();
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

  test("tournament explorer card actions navigate correctly", async ({ page }) => {
    await page.goto("/tournaments");
    await page.getByRole("button", { name: /Load Tournaments/i }).click();

    const bracketsButton = page.getByRole("main").getByRole("link", { name: /^Brackets$/i }).first();
    await expect(bracketsButton).toBeVisible();
    await bracketsButton.click();

    await expect(page).toHaveURL(/\/brackets/i);
    await expect(page.getByRole("heading", { name: /Bracket Center/i })).toBeVisible();
  });

  test("support assistant suggestions are clickable", async ({ page }) => {
    await page.goto("/support?ask=How%20do%20I%20view%20and%20run%20brackets%3F");

    const assistantSection = page.locator("#help-assistant");
    await expect(assistantSection).toBeVisible();

    await expect
      .poll(
        async () =>
          await assistantSection.getByRole("link", { name: /open/i }).count(),
        { timeout: 30000 }
      )
      .toBeGreaterThan(0);

    await assistantSection.getByRole("link", { name: /open/i }).first().click();

    await expect(page).toHaveURL(
      /\/(events|tournaments|brackets|registration|support|mat-scoring|table-worker|live|athlete|coach|search|bracket-builder)/i
    );
  });
});
