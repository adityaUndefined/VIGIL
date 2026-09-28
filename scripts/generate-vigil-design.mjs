import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Stitch, StitchToolClient } from "@google/stitch-sdk";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const projectFile = path.join(root, ".stitch-project.json");
const outputDir = path.join(root, "design", "stitch");

const prompt = `Design the real VIGIL main page as a polished desktop security-review workbench at 1440x1000. It is an existing local-first application, not a marketing page. Preserve the current compact information architecture: a simple VIGIL header with dynamic local-model availability at right; then a two-column workspace. The left panel is the input workflow: message/webpage review heading, three example buttons (Clean message, Campus fee scam, Hidden agent instruction), labeled empty textarea, character count, primary Analyze content button; below a divider, proposed agent-action review with a select and Check action button, plus a simulation-only note. The right panel is an inspection output with a neutral empty state and ALLOW/WARN/DENY outcome key. Its populated state needs room for verdict, local-model status, independent verification note, explanation, evidence list, and a plain-language warning.

Match the existing product identity: warm pale sage-gray background, white surfaces, deep forest green for primary actions, charcoal-green text, quiet gray-green borders, restrained amber and red only for risk. Use a premium, understated SaaS visual style with a disciplined 8px spacing rhythm, legible system sans typography, accessible contrast, subtle borders/shadows, and responsive behavior. Keep the desktop hierarchy efficient and calm. No gradients, glass, decorative AI motifs, fake scan data, or invented navigation/features. This is the main application page, not a dashboard or landing page.`;

const refinement = `Make a final polish pass on this existing VIGIL desktop screen. Preserve its two-column workflow, branding, warm pale sage-gray canvas, white surfaces, forest-green primary action, quiet gray-green borders, and restrained amber/red risk colors. Keep both panels aligned to the same available height, but let the left workflow stack naturally with consistent 16–24px gaps; do not force the form and action review to opposite ends with a large artificial blank gap. Let the textarea absorb a little extra height where useful. Keep the empty result state vertically centered so the full canvas remains balanced.

Meet the existing typography requirement: use a legible system sans/Geist family for all interface text and headings, not serif display type. Keep the hierarchy clear (main heading 28–32px, section headings 20–22px, body 15–16px, labels at least 13px), with strong contrast and comfortable line height. Use the consistent 8px spacing rhythm. Keep buttons and the select at least 40px tall. Add an unmistakable focus-visible ring to every button, preset, select, and textarea; keep semantic heading levels and explicit labels.

Preserve exactly these controls and labels: Clean message, Campus fee scam, Hidden agent instruction; an empty, explicitly labeled textarea for message or HTML payload; a character count; Analyze content; a proposed-action selector with Open the link, Send private information, Send credentials or OTP, Make a payment, and Summarize the message; Check action; and a small note that the action check is simulation only. Keep the result area unpopulated with room for real decision output, local-model state, independent verification, explanation, evidence, and a plain-language warning. Show ALLOW, WARN, and DENY as labeled decision outcomes. Remove statements that imply an outcome has verified something or identified malicious content; retain only one concise note that these heuristic outcomes are not guarantees. Color must not be the only distinction.

Use one neutral top-right local-model status placeholder only, such as “Local model · —”. Remove any “Standby” or other hardcoded readiness claim and do not repeat the status in the result panel. Make the empty state neutral and accurate (for example, “No review yet”), not a readiness claim. Remove redundant decorative icons and mini-headings, including the separate “Evaluation framework” label. Do not add invented navigation, audit log, settings, accounts, analytics, fake scan results, unsupported security claims, hardcoded model/engine values, or decorative imagery. Keep the layout compact but not cramped and responsive at narrower widths.

Accessibility finishing pass: preserve the current visual layout and labels. Mark every purely decorative Material Symbols icon with aria-hidden="true" so icon ligature names are not announced; keep each control's visible text as its accessible name. Keep the preset buttons grouped and both form controls explicitly associated with their labels. Provide a clearly visible keyboard-only focus-visible outline/ring on every interactive control. Do not introduce new controls or change the required labels.`;

async function loadSavedProjectId() {
  if (process.env.STITCH_PROJECT_ID) return process.env.STITCH_PROJECT_ID;
  try {
    const saved = JSON.parse(await readFile(projectFile, "utf8"));
    return saved.projectId;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    return null;
  }
}

async function main() {
  if (!process.env.STITCH_ACCESS_TOKEN || !process.env.GOOGLE_CLOUD_PROJECT) {
    throw new Error(
      "This Stitch endpoint requires OAuth. Set STITCH_ACCESS_TOKEN and GOOGLE_CLOUD_PROJECT; STITCH_API_KEY alone was rejected.",
    );
  }

  // SDK 0.3.5 prefers STITCH_API_KEY when both auth env vars exist, but this
  // Stitch endpoint currently rejects API-key auth. Keep this client OAuth-only.
  const configuredApiKey = process.env.STITCH_API_KEY;
  delete process.env.STITCH_API_KEY;
  const client = new StitchToolClient({
    accessToken: process.env.STITCH_ACCESS_TOKEN,
    projectId: process.env.GOOGLE_CLOUD_PROJECT,
    timeout: 300_000,
  });
  if (configuredApiKey) process.env.STITCH_API_KEY = configuredApiKey;

  try {
    const sdk = new Stitch(client);
    let projectId = await loadSavedProjectId();
    let project;
    if (projectId) {
      project = sdk.project(projectId);
    } else {
      // @google/stitch-sdk 0.3.x accepts the project title as a string.
      project = await sdk.createProject("VIGIL — Local Security Review");
      projectId = project.id;
      await writeFile(projectFile, `${JSON.stringify({ projectId }, null, 2)}\n`);
    }

    const screenMetaPath = path.join(outputDir, "screen.json");
    let previousScreenId = null;
    try {
      previousScreenId = JSON.parse(await readFile(screenMetaPath, "utf8")).screenId;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    const screen = previousScreenId
      ? await project.screen(previousScreenId).edit(refinement, "DESKTOP")
      : await project.generate(prompt, "DESKTOP");
    if (!screen?.id) throw new Error("Stitch returned no screen for the VIGIL design prompt.");

    await mkdir(outputDir, { recursive: true });
    // This SDK release returns signed artifact URLs from getHtml()/getImage().
    const [htmlUrl, imageUrl] = await Promise.all([screen.getHtml(), screen.getImage()]);
    if (!htmlUrl || !imageUrl) throw new Error("Stitch did not return both screen artifacts.");
    const [htmlResponse, imageResponse] = await Promise.all([fetch(htmlUrl), fetch(imageUrl)]);
    if (!htmlResponse.ok || !imageResponse.ok) {
      throw new Error(`Could not download screen artifacts (HTML ${htmlResponse.status}, image ${imageResponse.status}).`);
    }
    const [html, image] = await Promise.all([htmlResponse.text(), imageResponse.arrayBuffer()]);
    await Promise.all([
      writeFile(path.join(outputDir, "vigil-desktop.html"), html, "utf8"),
      writeFile(path.join(outputDir, "vigil-desktop.png"), Buffer.from(image)),
      writeFile(
        path.join(outputDir, "screen.json"),
        `${JSON.stringify({ projectId, screenId: screen.id, prompt, refinement: previousScreenId ? refinement : null }, null, 2)}\n`,
      ),
    ]);

    console.log(`Generated screen ${screen.id} in Stitch project ${projectId}.`);
    console.log(`Saved reference HTML and screenshot to ${path.relative(root, outputDir)}.`);
  } finally {
    await client.close();
  }
}

main().catch((error) => {
  console.error(`Stitch design generation failed: ${error.message}`);
  process.exitCode = 1;
});
