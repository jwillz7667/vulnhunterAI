// =============================================================================
// @vulnhunter/scanner - Code Analysis Module Barrel Export
// =============================================================================

export { SASTEngine } from "./sast.js";
export { SecretScanner } from "./secrets.js";
export { DependencyScanner } from "./deps.js";
export {
  type VulnerabilityPattern,
  patternsByLanguage,
  extensionToLanguage,
  allPatterns,
  jsPatterns,
  pythonPatterns,
  goPatterns,
  javaPatterns,
  phpPatterns,
} from "./patterns/index.js";
