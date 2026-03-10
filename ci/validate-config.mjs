import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "yaml";
import { validateAndNormalizeConfigV1 } from "../src/common/config.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

const files = process.argv.slice(2);
if (!files.length) {
  console.error("Usage: node ci/validate-config.mjs <config.yaml> [more...]");
  process.exit(2);
}

let hadError = false;
for (const file of files) {
  try {
    const fullPath = path.resolve(repoRoot, file);
    const text = await fs.readFile(fullPath, "utf8");
    const parsed = yaml.parse(text);
    validateAndNormalizeConfigV1(parsed);
    console.log(`OK: ${file}`);
  } catch (err) {
    hadError = true;
    console.error(`ERROR: ${file}`);
    console.error(String(err?.message || err));
    const problems = Array.isArray(err?.details?.problems) ? err.details.problems : [];
    if (problems.length > 0) {
      console.error("Validation problems:");
      for (const problem of problems) {
        const pathLabel = problem?.path ? String(problem.path) : "$";
        const message = problem?.message ? String(problem.message) : "Invalid value";
        console.error(`- ${pathLabel}: ${message}`);
      }
    }
  }
}

process.exit(hadError ? 1 : 0);
