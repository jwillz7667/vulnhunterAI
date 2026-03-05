// =============================================================================
// VulnHunter AI - Web Scanner Module Barrel Export
// =============================================================================
// Re-exports all web vulnerability scanner modules and the ScanModule interface.
// =============================================================================

// ScanModule interface (shared by all scanner modules)
export type { ScanModule } from "./xss.js";

// Individual Scanners
export { XssScanner } from "./xss.js";
export { SqliScanner } from "./sqli.js";
export { SsrfScanner } from "./ssrf.js";
export { IdorScanner } from "./idor.js";
export { AuthBypassScanner } from "./auth-bypass.js";
export { CorsScanner } from "./cors.js";
export { HeadersScanner } from "./headers.js";
export { ApiFuzzer } from "./api-fuzzer.js";
export { GraphqlScanner } from "./graphql.js";

// ---------------------------------------------------------------------------
// Convenience: Registry of all web scanners
// ---------------------------------------------------------------------------

import { XssScanner } from "./xss.js";
import { SqliScanner } from "./sqli.js";
import { SsrfScanner } from "./ssrf.js";
import { IdorScanner } from "./idor.js";
import { AuthBypassScanner } from "./auth-bypass.js";
import { CorsScanner } from "./cors.js";
import { HeadersScanner } from "./headers.js";
import { ApiFuzzer } from "./api-fuzzer.js";
import { GraphqlScanner } from "./graphql.js";

import type { ScanModule } from "./xss.js";

/**
 * Creates an array of all available web scanner module instances.
 * Useful for the scan engine to iterate and execute all modules.
 */
export function createAllWebScanners(): ScanModule[] {
  return [
    new XssScanner(),
    new SqliScanner(),
    new SsrfScanner(),
    new IdorScanner(),
    new AuthBypassScanner(),
    new CorsScanner(),
    new HeadersScanner(),
    new ApiFuzzer(),
    new GraphqlScanner(),
  ];
}

/**
 * Creates a single web scanner module by name.
 * Returns null if the name is not recognized.
 */
export function createWebScanner(name: string): ScanModule | null {
  switch (name.toLowerCase()) {
    case "xss":
      return new XssScanner();
    case "sqli":
      return new SqliScanner();
    case "ssrf":
      return new SsrfScanner();
    case "idor":
      return new IdorScanner();
    case "auth-bypass":
    case "auth_bypass":
      return new AuthBypassScanner();
    case "cors":
      return new CorsScanner();
    case "headers":
      return new HeadersScanner();
    case "api-fuzzer":
    case "api_fuzzer":
      return new ApiFuzzer();
    case "graphql":
      return new GraphqlScanner();
    default:
      return null;
  }
}

/**
 * List of all available web scanner module names.
 */
export const WEB_SCANNER_NAMES: readonly string[] = [
  "xss",
  "sqli",
  "ssrf",
  "idor",
  "auth-bypass",
  "cors",
  "headers",
  "api-fuzzer",
  "graphql",
] as const;
