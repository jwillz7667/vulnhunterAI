import { executeScanWithPersistence, prisma } from "@vulnhunter/core";
import { ScanType } from "@vulnhunter/core";

const SCAN_TYPE_MAP: Record<string, ScanType> = {
  full: ScanType.Full,
  recon: ScanType.Recon,
  web: ScanType.Web,
  code: ScanType.Code,
  network: ScanType.Network,
  cloud: ScanType.Cloud,
  smart_contract: ScanType.SmartContract,
};

export async function scanTarget(args: {
  target: string;
  scanType?: string;
  maxDepth?: number;
}): Promise<{ content: Array<{ type: "text"; text: string }> }> {
  const scanType = SCAN_TYPE_MAP[args.scanType || "full"] ?? ScanType.Full;

  try {
    const { scanId, result } = await executeScanWithPersistence({
      target: args.target,
      scanType,
      options: {
        maxDepth: args.maxDepth || 3,
        rateLimit: 10,
        requestTimeoutMs: 30000,
        scanTimeoutMs: 300000,
        maxConcurrency: 10,
        maxRedirects: 5,
        enableCookies: true,
        scopeRestrictions: [],
        enabledModules: [],
        aiPayloadGeneration: false,
        exploitChainDetection: false,
      },
    });

    const output = {
      scanId,
      target: args.target,
      scanType: args.scanType || "full",
      status: result.status,
      findingsCount: result.findings.length,
      findings: result.findings.slice(0, 20).map((f) => ({
        title: f.vulnerability.title,
        severity: f.vulnerability.severity,
        category: f.vulnerability.category,
        cvssScore: f.vulnerability.cvssScore,
        endpoint: f.vulnerability.endpoint,
        confidence: f.confidence,
        module: f.module,
      })),
      stats: {
        durationMs: result.stats.durationMs,
        modulesCompleted: result.stats.modulesCompleted,
        modulesFailed: result.stats.modulesFailed,
        findingsBySeverity: result.stats.findingsBySeverity,
      },
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
            {
              error: errMsg,
              target: args.target,
              scanType: args.scanType || "full",
              message: `Scan failed: ${errMsg}`,
            },
            null,
            2,
          ),
        },
      ],
    };
  }
}
