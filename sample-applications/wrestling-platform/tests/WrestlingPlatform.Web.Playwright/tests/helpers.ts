import { expect, Page } from "@playwright/test";

export async function signInDemoCoach(page: Page): Promise<void> {
  await page.goto("/");

  if (await page.getByRole("button", { name: /Sign Out/i }).isVisible().catch(() => false)) {
    return;
  }

  const demoCoachButton = page.getByRole("button", { name: /Demo Coach/i });
  if (await demoCoachButton.isVisible().catch(() => false)) {
    await demoCoachButton.click();
  } else {
    await page.getByPlaceholder("email").fill("demo.coach@pinpointarena.local");
    await page.getByPlaceholder("password").fill("DemoPass!123");
    await page.getByRole("button", { name: /^Sign In$/i }).click();
  }

  await expect(page.getByRole("button", { name: /Sign Out/i })).toBeVisible();
}

export async function applyWorkflowFromLab(page: Page): Promise<void> {
  await page.goto("/lab");
  await page.getByRole("button", { name: /Load Demo Showcase/i }).first().click();
  await expect(page.getByRole("heading", { name: /Bracket \+ Match Viewer/i })).toBeVisible();
  await page.getByRole("button", { name: /Apply IDs To Workflow/i }).click();
  await expect(page.getByText(/Workflow context updated/i)).toBeVisible();
}
