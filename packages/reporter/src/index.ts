export { ReportGenerator } from "./generator.js";
export type {
  ReportVulnerability,
  ReportConfig,
  ReportStatistics,
  GeneratedReport,
} from "./generator.js";
export { calculateCvss, calculateCvssFromVector, buildVector, parseVector, getSeverity, estimateCvss } from "./cvss.js";
export type { CvssMetrics, CvssResult } from "./cvss.js";
export { getCweForCategory, getCweById, getAllCwesForCategory, getOwaspMapping, getAllCweEntries } from "./cwe-mapper.js";
export type { CweEntry } from "./cwe-mapper.js";
export { mapToCompliance, getSupportedFrameworks } from "./compliance.js";
export type { ComplianceControl, ComplianceResult } from "./compliance.js";
export { generateMarkdown } from "./formats/markdown.js";
export { generateHtml } from "./formats/html.js";
export { generateJson } from "./formats/json.js";
