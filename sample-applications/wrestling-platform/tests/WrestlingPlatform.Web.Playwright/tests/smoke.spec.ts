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

    const drawerToggle = page.getByRole("button", { name: /open navigation menu|menu/i }).first();
    const isMobileLayout = (page.viewportSize()?.width ?? 1280) <= 900;

    for (const target of navTargets) {
      if (isMobileLayout) {
        await drawerToggle.click();
        const drawerLink = page.locator("aside.mud-drawer a.mud-nav-link").filter({ hasText: new RegExp(`^${target.label}$`, "i") }).first();
        await expect(drawerLink).toBeVisible();
        await drawerLink.click();
      } else {
        const link = page.getByRole("link", { name: new RegExp(`^${target.label}$`, "i") }).first();
        await link.click();
      }
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
