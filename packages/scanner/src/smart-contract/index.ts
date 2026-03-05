// =============================================================================
// @vulnhunter/scanner - Smart Contract Module Barrel Export
// =============================================================================

export { SolidityAnalyzer } from "./solidity.js";
export {
  type SolidityVulnerabilityPattern,
  SolidityVulnerabilityCategory,
  PATTERN_DATABASE,
  getPatternsByCategory,
  getPatternsBySeverity,
  getPatternById,
} from "./patterns.js";
