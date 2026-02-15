import { expect, test } from "@playwright/test";

test.describe("PinPoint Arena smoke", () => {
  test("home renders and core nav works", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /Competition Command Center/i })).toBeVisible();

    const navTargets = [
      { label: "Registration", heading: /Tournament Registration Center/i },
      { label: "Bracket Center", heading: /Bracket Center/i },
      { label: "Table Worker", heading: /Table Worker Station/i },
      { label: "Mat Scoring", heading: /Mat-Side Real-Time Scoring/i },
      { label: "Live Hub", heading: /Live Match Hub/i },
      { label: "Recruiting Hub", heading: /College Recruiting Hub/i }
    ];

    for (const target of navTargets) {
      await page.getByRole("link", { name: new RegExp(`^${target.label}$`, "i") }).first().click();
      await expect(page.getByRole("heading", { name: target.heading })).toBeVisible();
    }
  });

  test("table-worker can load tournament list", async ({ page }) => {
    await page.goto("/table-worker");
    await page.getByRole("button", { name: /Refresh/i }).click();
    await expect(page.locator(".list-item").first()).toBeVisible();
  });

  test("bracket center loads visual bundle for first event", async ({ page }) => {
    await page.goto("/brackets");
    await page.getByRole("button", { name: /Refresh Events/i }).click();
    await page.locator(".list-item .btn.secondary").first().click();
    await expect(page.getByRole("heading", { name: /Bracket Center/i })).toBeVisible();
    await expect(page.locator(".panel").nth(1)).toBeVisible();
  });

  test("state dropdowns are populated", async ({ page }) => {
    await page.goto("/registration");

    const stateSelect = page.locator("section:has-text('Search Tournaments') select").first();
    await expect(stateSelect).toBeVisible();

    const optionCount = await stateSelect.locator("option").count();
    expect(optionCount).toBeGreaterThan(40);
  });
});
