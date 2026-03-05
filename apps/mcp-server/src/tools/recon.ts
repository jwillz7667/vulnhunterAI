export async function reconDomain(args: {
  domain: string;
  modules?: string[];
}): Promise<{ content: Array<{ type: "text"; text: string }> }> {
  const requestedModules = args.modules || ["subdomain", "dns", "ports", "tech", "crawl"];
  const results: Record<string, unknown> = {};

  try {
    // Dynamically import scanner modules
    const { SubdomainEnumerator, DnsEnumerator, PortScanner, TechDetector, WebCrawler } =
      await import("@vulnhunter/scanner");

    const moduleOptions: Record<string, unknown> = {
      maxDepth: 3,
      rateLimit: 10,
      requestTimeoutMs: 30000,
      maxConcurrency: 5,
      customHeaders: {},
      userAgent: "VulnHunter/1.0 (Recon; +https://vulnhunter.ai)",
      maxRedirects: 5,
      enableCookies: true,
      scopeRestrictions: [],
    };

    const moduleMap: Record<string, { name: string; instance: any }> = {
      subdomain: { name: "Subdomain Enumeration", instance: new SubdomainEnumerator() },
      dns: { name: "DNS Enumeration", instance: new DnsEnumerator() },
      ports: { name: "Port Scanning", instance: new PortScanner() },
      tech: { name: "Technology Detection", instance: new TechDetector() },
      crawl: { name: "Web Crawling", instance: new WebCrawler() },
    };

    for (const modKey of requestedModules) {
      const mod = moduleMap[modKey];
      if (!mod) {
        results[modKey] = { error: `Unknown module: ${modKey}` };
        continue;
      }

      try {
        if (mod.instance.init) {
          await mod.instance.init(args.domain, moduleOptions);
        }

        const findings: unknown[] = [];
        const gen = mod.instance.execute(args.domain, moduleOptions);
        for await (const finding of gen) {
          findings.push({
            title: finding.vulnerability?.title ?? "Finding",
            severity: finding.vulnerability?.severity ?? "info",
            endpoint: finding.vulnerability?.endpoint,
            evidence: finding.vulnerability?.evidence?.description,
          });
          if (findings.length >= 50) break; // Cap results
        }

        if (mod.instance.cleanup) {
          await mod.instance.cleanup();
        }

        results[modKey] = {
          module: mod.name,
          count: findings.length,
          findings,
        };
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        results[modKey] = { module: mod.name, error: errMsg };
      }
    }

    const output = {
      domain: args.domain,
      modules: requestedModules,
      status: "completed",
      results,
    };

    return {
      content: [{ type: "text" as const, text: JSON.stringify(output, null, 2) }],
    };
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            { domain: args.domain, error: errMsg, message: `Recon failed: ${errMsg}` },
            null,
            2,
          ),
        },
      ],
    };
  }
}
