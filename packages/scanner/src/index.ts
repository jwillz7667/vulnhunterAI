// =============================================================================
// @vulnhunter/scanner - Main Package Barrel Export
// =============================================================================
// Re-exports all scanner modules, the scan engine, and utility types.
// This is the primary entry point for consumers of the @vulnhunter/scanner
// package.
// =============================================================================

// ---------------------------------------------------------------------------
// Core Engine
// ---------------------------------------------------------------------------

export { ScanEngine, createDefaultEngine } from "./engine.js";
export type { ScanModule } from "./engine.js";

// ---------------------------------------------------------------------------
// Reconnaissance Modules
// ---------------------------------------------------------------------------

export {
  SubdomainEnumerator,
  PortScanner,
  TechDetector,
  WebCrawler,
  DnsEnumerator,
} from "./recon/index.js";

// ---------------------------------------------------------------------------
// Web Vulnerability Scanners
// ---------------------------------------------------------------------------

export {
  XssScanner,
  SqliScanner,
  SsrfScanner,
  IdorScanner,
  AuthBypassScanner,
  CorsScanner,
  HeadersScanner,
  ApiFuzzer,
  GraphqlScanner,
  createAllWebScanners,
  createWebScanner,
  WEB_SCANNER_NAMES,
} from "./web/index.js";

// ---------------------------------------------------------------------------
// Network Scanners
// ---------------------------------------------------------------------------

export {
  SslTlsScanner,
  ServiceEnumerator,
  NetworkMisconfigScanner,
} from "./network/index.js";

// ---------------------------------------------------------------------------
// Code Analysis
// ---------------------------------------------------------------------------

export {
  SASTEngine,
  SecretScanner,
  DependencyScanner,
} from "./code/index.js";

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
} from "./code/index.js";

// ---------------------------------------------------------------------------
// Cloud Scanners
// ---------------------------------------------------------------------------

export {
  AwsScanner,
  S3BucketScanner,
  GcpScanner,
  AzureScanner,
} from "./cloud/index.js";

// ---------------------------------------------------------------------------
// Smart Contract Analysis
// ---------------------------------------------------------------------------

export {
  SolidityAnalyzer,
  SolidityVulnerabilityCategory,
  PATTERN_DATABASE,
  getPatternsByCategory,
  getPatternsBySeverity,
  getPatternById,
} from "./smart-contract/index.js";

export type { SolidityVulnerabilityPattern } from "./smart-contract/index.js";

// ---------------------------------------------------------------------------
// Template Engine
// ---------------------------------------------------------------------------

export { TemplateLoader, loadTemplatesFromDirectory } from "./templates/loader.js";
export type { NucleiTemplate } from "./templates/loader.js";

// ---------------------------------------------------------------------------
// Convenience Factory: Creates a ScanEngine with ALL built-in modules
// ---------------------------------------------------------------------------

import { ScanEngine } from "./engine.js";

/**
 * Creates a ScanEngine pre-loaded with every available built-in scanner module.
 * This is the "batteries-included" experience for consumers who want to run
 * all scan types.
 */
export async function createFullEngine(): Promise<ScanEngine> {
  const engine = new ScanEngine();

  // Recon modules
  const { SubdomainEnumerator } = await import("./recon/subdomain.js");
  const { DnsEnumerator } = await import("./recon/dns.js");
  const { PortScanner } = await import("./recon/port-scan.js");
  const { TechDetector } = await import("./recon/tech-detect.js");
  const { WebCrawler } = await import("./recon/crawler.js");

  // Web modules
  const { XssScanner } = await import("./web/xss.js");
  const { SqliScanner } = await import("./web/sqli.js");
  const { SsrfScanner } = await import("./web/ssrf.js");
  const { IdorScanner } = await import("./web/idor.js");
  const { AuthBypassScanner } = await import("./web/auth-bypass.js");
  const { CorsScanner } = await import("./web/cors.js");
  const { HeadersScanner } = await import("./web/headers.js");
  const { ApiFuzzer } = await import("./web/api-fuzzer.js");
  const { GraphqlScanner } = await import("./web/graphql.js");

  // Network modules
  const { SslTlsScanner } = await import("./network/ssl-tls.js");
  const { ServiceEnumerator } = await import("./network/service-enum.js");
  const { NetworkMisconfigScanner } = await import("./network/misconfig.js");

  // Cloud modules
  const { AwsScanner } = await import("./cloud/aws.js");
  const { GcpScanner } = await import("./cloud/gcp.js");
  const { AzureScanner } = await import("./cloud/azure.js");
  const { S3BucketScanner } = await import("./cloud/s3.js");

  // Smart contract modules
  const { SolidityAnalyzer } = await import("./smart-contract/solidity.js");

  // Template engine
  const { TemplateLoader } = await import("./templates/loader.js");

  // Code analysis modules
  const { SASTEngine } = await import("./code/sast.js");
  const { SecretScanner } = await import("./code/secrets.js");
  const { DependencyScanner } = await import("./code/deps.js");

  engine.registerModules([
    // Recon
    new SubdomainEnumerator(),
    new DnsEnumerator(),
    new PortScanner(),
    new TechDetector(),
    new WebCrawler(),
    // Web
    new XssScanner(),
    new SqliScanner(),
    new SsrfScanner(),
    new IdorScanner(),
    new AuthBypassScanner(),
    new CorsScanner(),
    new HeadersScanner(),
    new ApiFuzzer(),
    new GraphqlScanner(),
    // Network
    new SslTlsScanner(),
    new ServiceEnumerator(),
    new NetworkMisconfigScanner(),
    // Cloud
    new AwsScanner(),
    new GcpScanner(),
    new AzureScanner(),
    new S3BucketScanner(),
    // Smart Contract
    new SolidityAnalyzer(),
    // Templates
    new TemplateLoader(),
    // Code Analysis
    new SASTEngine(),
    new SecretScanner(),
    new DependencyScanner(),
  ]);

  return engine;
}
