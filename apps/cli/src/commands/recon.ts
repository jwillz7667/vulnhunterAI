// =============================================================================
// @vulnhunter/cli - Recon Command
// =============================================================================
// Runs reconnaissance-only modules against a target domain. Discovers
// subdomains, open ports, technologies, crawled URLs, and DNS records.
// Outputs structured recon data for subsequent targeted scanning.
// =============================================================================

import { Command } from "commander";
import fs from "node:fs";
import path from "node:path";
import { ScanProgressDisplay } from "../ui/progress.js";
import { renderReconTable } from "../ui/table.js";
import { getConfigValue } from "./config.js";

interface ReconResult {
  domain: string;
  subdomains: string[];
  openPorts: Array<{ host: string; port: number; service?: string }>;
  technologies: string[];
  crawledUrls: string[];
  dnsRecords: Record<string, string[]>;
  startTime: string;
  endTime: string;
  durationMs: number;
}

/** Shared scanner module options for recon. */
const RECON_MODULE_OPTS = {
  maxDepth: 3,
  rateLimit: 10,
  requestTimeoutMs: 30_000,
  maxConcurrency: 5,
  customHeaders: {},
  userAgent: "VulnHunter/1.0 (Recon; +https://vulnhunter.ai)",
  maxRedirects: 5,
  enableCookies: true,
  scopeRestrictions: [],
};

/**
 * Enumerates subdomains using the real SubdomainEnumerator scanner module.
 */
async function enumerateSubdomains(domain: string): Promise<string[]> {
  const { SubdomainEnumerator } = await import("@vulnhunter/scanner");
  const enumerator = new SubdomainEnumerator();
  if (enumerator.init) await enumerator.init(domain, RECON_MODULE_OPTS);
  const subdomains: string[] = [];
  try {
    for await (const finding of enumerator.execute(domain, RECON_MODULE_OPTS)) {
      const ep = finding.vulnerability?.endpoint ?? finding.vulnerability?.title;
      if (ep && !subdomains.includes(ep)) subdomains.push(ep);
      if (subdomains.length >= 200) break;
    }
  } finally {
    if (enumerator.cleanup) await enumerator.cleanup();
  }
  return subdomains;
}

/**
 * Scans ports using the real PortScanner module.
 */
async function scanPorts(
  domain: string,
  subdomains: string[],
): Promise<Array<{ host: string; port: number; service?: string }>> {
  const { PortScanner } = await import("@vulnhunter/scanner");
  const scanner = new PortScanner();
  const results: Array<{ host: string; port: number; service?: string }> = [];
  const hosts = [domain, ...subdomains.slice(0, 5)];

  for (const host of hosts) {
    if (scanner.init) await scanner.init(host, RECON_MODULE_OPTS);
    try {
      for await (const finding of scanner.execute(host, RECON_MODULE_OPTS)) {
        const v = finding.vulnerability;
        if (v) {
          const portMatch = v.title?.match(/port\s+(\d+)/i) || v.endpoint?.match(/:(\d+)/);
          const port = portMatch ? parseInt(portMatch[1]!, 10) : 0;
          if (port > 0) {
            results.push({ host, port, service: v.evidence?.description || v.category });
          }
        }
        if (results.length >= 200) break;
      }
    } finally {
      if (scanner.cleanup) await scanner.cleanup();
    }
    if (results.length >= 200) break;
  }

  return results;
}

/**
 * Detects technologies using the real TechDetector module.
 */
async function detectTechnologies(domain: string): Promise<string[]> {
  const { TechDetector } = await import("@vulnhunter/scanner");
  const detector = new TechDetector();
  if (detector.init) await detector.init(domain, RECON_MODULE_OPTS);
  const techs: string[] = [];
  try {
    for await (const finding of detector.execute(domain, RECON_MODULE_OPTS)) {
      const name = finding.vulnerability?.title ?? finding.vulnerability?.evidence?.description;
      if (name && !techs.includes(name)) techs.push(name);
      if (techs.length >= 50) break;
    }
  } finally {
    if (detector.cleanup) await detector.cleanup();
  }
  return techs;
}

/**
 * Crawls URLs using the real WebCrawler module.
 */
async function crawlUrls(
  domain: string,
  depth: number,
): Promise<string[]> {
  const { WebCrawler } = await import("@vulnhunter/scanner");
  const crawler = new WebCrawler();
  const opts = { ...RECON_MODULE_OPTS, maxDepth: depth };
  if (crawler.init) await crawler.init(domain, opts);
  const urls: string[] = [];
  try {
    for await (const finding of crawler.execute(domain, opts)) {
      const url = finding.vulnerability?.endpoint ?? finding.vulnerability?.target;
      if (url && !urls.includes(url)) urls.push(url);
      if (urls.length >= 500) break;
    }
  } finally {
    if (crawler.cleanup) await crawler.cleanup();
  }
  return urls;
}

/**
 * Resolves DNS records using the real DnsEnumerator module.
 */
async function resolveDns(domain: string): Promise<Record<string, string[]>> {
  const { DnsEnumerator } = await import("@vulnhunter/scanner");
  const enumerator = new DnsEnumerator();
  if (enumerator.init) await enumerator.init(domain, RECON_MODULE_OPTS);
  const records: Record<string, string[]> = {};
  try {
    for await (const finding of enumerator.execute(domain, RECON_MODULE_OPTS)) {
      const v = finding.vulnerability;
      if (v) {
        const recordType = v.category?.toUpperCase() || "OTHER";
        if (!records[recordType]) records[recordType] = [];
        const value = v.evidence?.description ?? v.endpoint ?? v.title;
        if (value) records[recordType]!.push(value);
      }
      if (Object.values(records).flat().length >= 100) break;
    }
  } finally {
    if (enumerator.cleanup) await enumerator.cleanup();
  }
  return records;
}

/**
 * Registers the `recon` command with Commander.
 */
export function registerReconCommand(program: Command): void {
  program
    .command("recon <domain>")
    .description("Run reconnaissance against a target domain")
    .option("-s, --subdomain", "Enable subdomain enumeration", true)
    .option("-p, --ports", "Enable port scanning", true)
    .option("-t, --tech-detect", "Enable technology detection", true)
    .option("-c, --crawl", "Enable URL crawling", true)
    .option("--dns", "Enable DNS record resolution", true)
    .option("-d, --depth <depth>", "Crawl depth", "3")
    .option("-o, --output <path>", "Save results to file (JSON)")
    .option("--no-subdomain", "Disable subdomain enumeration")
    .option("--no-ports", "Disable port scanning")
    .option("--no-tech-detect", "Disable technology detection")
    .option("--no-crawl", "Disable URL crawling")
    .option("--no-dns", "Disable DNS resolution")
    .action(async (domain: string, opts: Record<string, unknown>) => {
      const chalk = (await import("chalk")).default;

      // Strip protocol if provided
      const cleanDomain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "");

      console.log();
      console.log(chalk.cyan.bold("  VulnHunter AI - Reconnaissance"));
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log(chalk.white(`  Target:   ${chalk.cyan.bold(cleanDomain)}`));
      console.log(chalk.white(`  Depth:    ${opts.depth}`));

      const enabledModules: string[] = [];
      if (opts.subdomain !== false) enabledModules.push("Subdomain Enumeration");
      if (opts.ports !== false) enabledModules.push("Port Scanning");
      if (opts.techDetect !== false) enabledModules.push("Technology Detection");
      if (opts.crawl !== false) enabledModules.push("URL Crawling");
      if (opts.dns !== false) enabledModules.push("DNS Resolution");

      console.log(chalk.white(`  Modules:  ${enabledModules.join(", ")}`));
      console.log(chalk.gray("  " + "\u2500".repeat(50)));
      console.log();

      const progress = new ScanProgressDisplay();
      await progress.start(`Starting reconnaissance on ${cleanDomain}...`);

      const startTime = new Date();
      const result: ReconResult = {
        domain: cleanDomain,
        subdomains: [],
        openPorts: [],
        technologies: [],
        crawledUrls: [],
        dnsRecords: {},
        startTime: startTime.toISOString(),
        endTime: "",
        durationMs: 0,
      };

      try {
        // Phase 1: DNS Resolution
        if (opts.dns !== false) {
          await progress.update({
            phase: "dns",
            module: "dns_recon",
            progressPercent: 5,
            message: `Resolving DNS records for ${cleanDomain}`,
            findingsCount: 0,
            endpointsTested: 0,
            requestsSent: 1,
          });
          result.dnsRecords = await resolveDns(cleanDomain);
        }

        // Phase 2: Subdomain Enumeration
        if (opts.subdomain !== false) {
          await progress.update({
            phase: "subdomain",
            module: "subdomain_enum",
            progressPercent: 20,
            message: `Enumerating subdomains for ${cleanDomain}`,
            findingsCount: 0,
            endpointsTested: 0,
            requestsSent: 15,
          });
          result.subdomains = await enumerateSubdomains(cleanDomain);
        }

        // Phase 3: Port Scanning
        if (opts.ports !== false) {
          await progress.update({
            phase: "portscan",
            module: "port_scan",
            progressPercent: 40,
            message: `Scanning ports on ${cleanDomain} and ${result.subdomains.length} subdomains`,
            findingsCount: 0,
            endpointsTested: result.subdomains.length + 1,
            requestsSent: 50,
          });
          result.openPorts = await scanPorts(cleanDomain, result.subdomains);
        }

        // Phase 4: Technology Detection
        if (opts.techDetect !== false) {
          await progress.update({
            phase: "tech_detect",
            module: "tech_detect",
            progressPercent: 65,
            message: `Detecting technologies on ${cleanDomain}`,
            findingsCount: 0,
            endpointsTested: result.subdomains.length + 1,
            requestsSent: 80,
          });
          result.technologies = await detectTechnologies(cleanDomain);
        }

        // Phase 5: URL Crawling
        if (opts.crawl !== false) {
          await progress.update({
            phase: "crawl",
            module: "crawler",
            progressPercent: 80,
            message: `Crawling URLs on ${cleanDomain} (depth: ${opts.depth})`,
            findingsCount: 0,
            endpointsTested: result.subdomains.length + 1,
            requestsSent: 120,
          });
          result.crawledUrls = await crawlUrls(cleanDomain, Number(opts.depth));
        }

        const endTime = new Date();
        result.endTime = endTime.toISOString();
        result.durationMs = endTime.getTime() - startTime.getTime();

        await progress.complete(
          `Reconnaissance completed in ${(result.durationMs / 1000).toFixed(1)}s`,
        );

        // Display results
        console.log();
        console.log(chalk.cyan.bold("  Reconnaissance Results"));
        console.log(chalk.gray("  " + "\u2500".repeat(50)));
        console.log(chalk.white(`  Domain:      ${chalk.cyan.bold(cleanDomain)}`));
        console.log(chalk.white(`  Subdomains:  ${chalk.green(String(result.subdomains.length))}`));
        console.log(chalk.white(`  Open Ports:  ${chalk.green(String(result.openPorts.length))}`));
        console.log(chalk.white(`  Technologies:${chalk.green(String(result.technologies.length))}`));
        console.log(chalk.white(`  URLs Found:  ${chalk.green(String(result.crawledUrls.length))}`));
        console.log(chalk.white(`  DNS Records: ${chalk.green(String(Object.keys(result.dnsRecords).length))} types`));
        console.log(chalk.white(`  Duration:    ${(result.durationMs / 1000).toFixed(1)}s`));
        console.log();

        // Render detailed tables
        await renderReconTable({
          subdomains: result.subdomains,
          openPorts: result.openPorts,
          technologies: result.technologies,
          crawledUrls: result.crawledUrls,
          dnsRecords: result.dnsRecords,
        });

        // Save output if requested
        if (opts.output) {
          const outputPath = path.resolve(opts.output as string);
          const dir = path.dirname(outputPath);
          if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
          }
          fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), "utf-8");
          console.log(chalk.green(`  \u2713 Results saved to ${outputPath}\n`));
        }

        // Suggest next steps
        console.log(chalk.gray("  Next steps:"));
        console.log(chalk.gray(`    vulnhunter scan ${cleanDomain} --type web    # Run web vulnerability scan`));
        console.log(chalk.gray(`    vulnhunter scan ${cleanDomain} --type full   # Run full security assessment`));
        console.log();
      } catch (err: any) {
        await progress.error(err.message || "Reconnaissance failed");
        process.exit(1);
      }
    });
}
