// =============================================================================
// @vulnhunter/scanner - Azure Misconfiguration Scanner
// =============================================================================
// Detects common Azure cloud misconfigurations including public Blob storage
// containers, exposed IMDS metadata endpoints, and App Service
// misconfigurations.
// =============================================================================

import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { generateUUID, createLogger } from "@vulnhunter/core";
import type { ScanModule } from "../engine.js";

const log = createLogger("azure-scanner");

const REQUEST_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// Blob Storage Patterns
// ---------------------------------------------------------------------------

const BLOB_URL_PATTERN = /([a-z0-9]{3,24})\.blob\.core\.windows\.net/i;

const COMMON_CONTAINER_NAMES = [
  "$web", "assets", "static", "media", "uploads", "files", "data",
  "backup", "backups", "logs", "images", "documents", "public",
  "private", "config", "temp", "tmp", "archive", "packages",
  "artifacts", "builds", "releases", "exports", "imports",
  "reports", "downloads", "content",
];

const SENSITIVE_BLOB_PATHS = [
  ".env", "config.json", "config.yml", "appsettings.json",
  "appsettings.Development.json", "appsettings.Production.json",
  "web.config", "secrets.json", "connectionstrings.json",
  "backup.sql", "dump.sql", "database.bak",
  "terraform.tfstate", "terraform.tfvars",
  ".git/config", ".git/HEAD",
  "id_rsa", "private.key", "server.pfx", "server.key",
  "credentials.json", "ServiceAccountKey.json",
];

// ---------------------------------------------------------------------------
// AzureScanner
// ---------------------------------------------------------------------------

export class AzureScanner implements ScanModule {
  readonly name = "cloud:azure";

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const hostname = this.extractHostname(target);

    log.info({ target, hostname }, "Starting Azure misconfiguration scan");

    // 1. Blob Storage Enumeration
    yield* this.enumerateBlobStorage(target, hostname, options);

    // 2. Metadata Endpoint Exposure (IMDS)
    yield* this.checkMetadataEndpoint(target, hostname);

    // 3. App Service Misconfiguration
    yield* this.checkAppServiceMisconfig(target, hostname);

    // 4. Azure-Specific Header Analysis
    yield* this.analyzeAzureHeaders(target, hostname);

    log.info({ target }, "Azure misconfiguration scan complete");
  }

  // -------------------------------------------------------------------------
  // Blob Storage Enumeration
  // -------------------------------------------------------------------------

  private async *enumerateBlobStorage(
    target: string,
    hostname: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    // Extract storage account from target URL if it's a blob URL
    const blobMatch = target.match(BLOB_URL_PATTERN);
    let storageAccountName: string | undefined;

    if (blobMatch) {
      storageAccountName = blobMatch[1];
    } else if (hostname) {
      // Derive potential storage account names from the hostname
      const baseName = hostname
        .replace(/\.[^.]+$/, "")
        .replace(/\./g, "")
        .replace(/-/g, "")
        .toLowerCase()
        .slice(0, 24);
      storageAccountName = baseName;
    }

    if (!storageAccountName) return;

    const maxContainers = (options.maxContainers as number) ?? COMMON_CONTAINER_NAMES.length;
    const containersToCheck = COMMON_CONTAINER_NAMES.slice(0, maxContainers);

    log.info(
      { storageAccountName, containerCount: containersToCheck.length },
      "Enumerating Azure Blob containers",
    );

    for (const containerName of containersToCheck) {
      const containerUrl = `https://${storageAccountName}.blob.core.windows.net/${containerName}`;

      // Check container listing (public read access)
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const listUrl = `${containerUrl}?restype=container&comp=list`;
        const response = await fetch(listUrl, {
          method: "GET",
          signal: controller.signal,
        });

        clearTimeout(timeout);

        if (response.ok) {
          const body = await response.text();

          if (body.includes("<EnumerationResults") || body.includes("<Blobs>") || body.includes("<Blob>")) {
            const blobCount = (body.match(/<Blob>/g) || []).length;

            yield this.createFinding(
              `Public Azure Blob Container: ${storageAccountName}/${containerName}`,
              `The Azure Blob Storage container "${containerName}" in storage account "${storageAccountName}" allows public listing. ${blobCount} blob(s) are enumerable. Anyone can list and download all files in this container.`,
              Severity.High,
              target,
              containerUrl,
              "CWE-284",
              7.5,
              95,
              {
                storageAccount: storageAccountName,
                containerName,
                publicListing: true,
                blobCount,
              },
              `Set the container access level to Private. Use Azure Portal or CLI: az storage container set-permission --name ${containerName} --account-name ${storageAccountName} --public-access off. Use SAS tokens for controlled access.`,
            );

            // Check for sensitive files
            yield* this.checkSensitiveBlobs(storageAccountName, containerName, target);
          }
        } else if (response.status === 404) {
          // Container doesn't exist, skip
        } else if (response.status === 403) {
          // Container exists but is not public (good)
          log.debug({ storageAccountName, containerName }, "Container exists but is private");
        }
      } catch {
        // Not accessible
      }
    }

    // Check for anonymous access to the storage account root
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const accountUrl = `https://${storageAccountName}.blob.core.windows.net/?comp=list`;
      const response = await fetch(accountUrl, {
        method: "GET",
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (response.ok) {
        const body = await response.text();
        if (body.includes("<Containers>") || body.includes("<Container>")) {
          yield this.createFinding(
            `Azure Storage Account Container Listing: ${storageAccountName}`,
            `The Azure storage account "${storageAccountName}" allows anonymous enumeration of all containers. This reveals the full container structure and aids in targeted attacks against individual containers.`,
            Severity.Medium,
            target,
            `https://${storageAccountName}.blob.core.windows.net/`,
            "CWE-284",
            5.3,
            90,
            { storageAccount: storageAccountName, accountListingEnabled: true },
            `Disable anonymous container listing on the storage account. Use Azure Resource Manager to enforce private access at the account level.`,
          );
        }
      }
    } catch {
      // Not accessible
    }
  }

  /**
   * Check for sensitive files in a publicly accessible container.
   */
  private async *checkSensitiveBlobs(
    storageAccountName: string,
    containerName: string,
    target: string,
  ): AsyncGenerator<Finding> {
    for (const filePath of SENSITIVE_BLOB_PATHS) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const blobUrl = `https://${storageAccountName}.blob.core.windows.net/${containerName}/${filePath}`;
        const response = await fetch(blobUrl, {
          method: "HEAD",
          signal: controller.signal,
        });

        clearTimeout(timeout);

        if (response.ok) {
          const contentLength = response.headers.get("content-length") ?? "unknown";
          const contentType = response.headers.get("content-type") ?? "unknown";

          yield this.createFinding(
            `Sensitive File Exposed in Azure Blob: ${filePath}`,
            `The file "${filePath}" is publicly accessible in Azure Blob container "${containerName}" (account: ${storageAccountName}). Size: ${contentLength} bytes, Type: ${contentType}.`,
            Severity.Critical,
            target,
            blobUrl,
            "CWE-538",
            9.1,
            90,
            {
              storageAccount: storageAccountName,
              containerName,
              filePath,
              fileSize: contentLength,
              contentType,
            },
            `Remove the sensitive file or restrict container access to Private. Rotate any credentials found in the file immediately.`,
          );
        }
      } catch {
        // File not accessible
      }
    }
  }

  // -------------------------------------------------------------------------
  // Metadata Endpoint Check (IMDS)
  // -------------------------------------------------------------------------

  private async *checkMetadataEndpoint(
    target: string,
    hostname: string,
  ): AsyncGenerator<Finding> {
    const metadataUrls = [
      "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
      "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
    ];

    for (const metaUrl of metadataUrls) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        // Azure IMDS requires the Metadata header
        const response = await fetch(metaUrl, {
          method: "GET",
          headers: { Metadata: "true" },
          signal: controller.signal,
          redirect: "manual",
        });

        clearTimeout(timeout);

        if (response.ok) {
          const body = await response.text();

          if (
            body.includes("compute") ||
            body.includes("vmId") ||
            body.includes("subscriptionId") ||
            body.includes("access_token") ||
            body.includes("resourceGroupName")
          ) {
            yield this.createFinding(
              "Azure Instance Metadata Service (IMDS) Accessible",
              `The Azure IMDS at ${metaUrl} is accessible. This exposes VM identity, subscription information, managed identity tokens, and other sensitive metadata. An attacker can use managed identity tokens to access Azure resources.`,
              Severity.Critical,
              target,
              metaUrl,
              "CWE-918",
              9.8,
              95,
              { metadataUrl: metaUrl, responseSnippet: body.slice(0, 500) },
              "Restrict network access to the IMDS endpoint (169.254.169.254). Use NSG rules to block IMDS access from application subnets. Implement managed identity with least-privilege RBAC roles.",
            );
          }
        }
      } catch {
        // Not accessible (expected and good)
      }
    }

    // SSRF to metadata via target
    if (hostname) {
      try {
        const ssrfUrl = `${target.replace(/\/$/, "")}/?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const response = await fetch(ssrfUrl, {
          headers: { Metadata: "true" },
          signal: controller.signal,
          redirect: "follow",
        });

        clearTimeout(timeout);

        if (response.ok) {
          const body = await response.text();
          if (body.includes("vmId") || body.includes("subscriptionId") || body.includes("access_token")) {
            yield this.createFinding(
              "SSRF to Azure Metadata Service via Target Application",
              `The target application at ${hostname} proxies requests to the Azure IMDS. This SSRF vulnerability allows stealing managed identity tokens and accessing Azure resources.`,
              Severity.Critical,
              target,
              ssrfUrl,
              "CWE-918",
              9.8,
              85,
              { ssrfUrl, metadataAccessible: true },
              "Fix the SSRF vulnerability. Block outbound requests to 169.254.169.254 via NSG rules. Use managed identity with least-privilege roles.",
            );
          }
        }
      } catch {
        // Expected
      }
    }
  }

  // -------------------------------------------------------------------------
  // App Service Misconfiguration
  // -------------------------------------------------------------------------

  private async *checkAppServiceMisconfig(
    target: string,
    hostname: string,
  ): AsyncGenerator<Finding> {
    if (!hostname) return;

    // Check if it's an Azure App Service
    const isAppService =
      hostname.endsWith(".azurewebsites.net") ||
      hostname.endsWith(".azurefd.net") ||
      hostname.endsWith(".azure-api.net");

    if (!isAppService) {
      // Check via headers for non-default domains
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const response = await fetch(target, {
          method: "HEAD",
          signal: controller.signal,
        });

        clearTimeout(timeout);

        const poweredBy = response.headers.get("x-powered-by") ?? "";
        const aspNet = response.headers.get("x-aspnet-version") ?? "";

        if (!poweredBy.includes("ASP.NET") && !aspNet) return;
      } catch {
        return;
      }
    }

    log.info({ hostname }, "Azure App Service detected, checking for misconfigurations");

    // Check for exposed Kudu (SCM) panel
    const scmHostname = hostname.replace(".azurewebsites.net", ".scm.azurewebsites.net");
    if (hostname.endsWith(".azurewebsites.net")) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const scmUrl = `https://${scmHostname}/`;
        const response = await fetch(scmUrl, {
          method: "GET",
          signal: controller.signal,
          redirect: "manual",
        });

        clearTimeout(timeout);

        if (response.ok || response.status === 200) {
          const body = await response.text();
          if (body.includes("Kudu") || body.includes("SCM") || body.includes("deployments")) {
            yield this.createFinding(
              "Azure App Service Kudu/SCM Panel Accessible",
              `The Kudu (SCM) management panel at ${scmUrl} is accessible. This panel provides deployment management, process explorer, console access, and debug tools. If authentication is not properly configured, attackers can deploy malicious code.`,
              Severity.High,
              target,
              scmUrl,
              "CWE-284",
              8.6,
              85,
              { scmHostname, kuduAccessible: true },
              "Restrict access to the SCM site. Enable authentication for the SCM endpoint. Use IP restrictions in the Azure Portal under Networking > Access restrictions for the Advanced tools (SCM) site.",
            );
          }
        }
      } catch {
        // SCM not accessible (good)
      }
    }

    // Check for information disclosure in headers
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const response = await fetch(target, {
        method: "HEAD",
        signal: controller.signal,
      });

      clearTimeout(timeout);

      // Check for server version disclosure
      const poweredBy = response.headers.get("x-powered-by");
      const aspNetVersion = response.headers.get("x-aspnet-version");
      const server = response.headers.get("server");

      if (poweredBy) {
        yield this.createFinding(
          "Azure App Service X-Powered-By Header Disclosure",
          `The App Service at ${hostname} discloses technology information via the X-Powered-By header (${poweredBy}). This helps attackers identify the technology stack for targeted exploits.`,
          Severity.Low,
          target,
          target,
          "CWE-200",
          3.7,
          80,
          { header: "X-Powered-By", value: poweredBy },
          "Remove the X-Powered-By header in web.config: <customHeaders><remove name=\"X-Powered-By\" /></customHeaders>. Or configure in Azure Portal > Configuration > General settings.",
        );
      }

      if (aspNetVersion) {
        yield this.createFinding(
          "ASP.NET Version Disclosure",
          `The App Service at ${hostname} discloses the ASP.NET version (${aspNetVersion}) via the X-AspNet-Version header. Version information aids attackers in identifying applicable CVEs.`,
          Severity.Low,
          target,
          target,
          "CWE-200",
          3.7,
          80,
          { header: "X-AspNet-Version", value: aspNetVersion },
          "Remove the X-AspNet-Version header in web.config: <httpRuntime enableVersionHeader=\"false\" />.",
        );
      }

      // Check for missing security headers
      const hasHsts = response.headers.has("strict-transport-security");
      const hasCsp = response.headers.has("content-security-policy");
      const hasXfo = response.headers.has("x-frame-options");

      if (!hasHsts && !hasCsp && !hasXfo) {
        yield this.createFinding(
          "Azure App Service Missing Security Headers",
          `The App Service at ${hostname} does not send critical security headers (Strict-Transport-Security, Content-Security-Policy, X-Frame-Options). This increases the risk of clickjacking, XSS, and protocol downgrade attacks.`,
          Severity.Medium,
          target,
          target,
          "CWE-693",
          5.3,
          75,
          { missingHeaders: ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"] },
          "Configure security headers in web.config or via middleware. Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers.",
        );
      }

      // Check HTTPS-only configuration
      if (hostname.endsWith(".azurewebsites.net")) {
        try {
          const httpController = new AbortController();
          const httpTimeout = setTimeout(() => httpController.abort(), REQUEST_TIMEOUT_MS);

          const httpResponse = await fetch(`http://${hostname}/`, {
            method: "HEAD",
            redirect: "manual",
            signal: httpController.signal,
          });

          clearTimeout(httpTimeout);

          if (httpResponse.status === 200) {
            yield this.createFinding(
              "Azure App Service HTTP Not Redirected to HTTPS",
              `The App Service at ${hostname} serves content over HTTP without redirecting to HTTPS. Azure App Service should have "HTTPS Only" enabled to force all traffic through TLS.`,
              Severity.Medium,
              target,
              `http://${hostname}/`,
              "CWE-319",
              5.3,
              80,
              { httpAccessible: true, httpsOnly: false },
              "Enable HTTPS Only in Azure Portal: App Service > Settings > TLS/SSL settings > HTTPS Only = On.",
            );
          }
        } catch {
          // HTTP not accessible, which is fine
        }
      }
    } catch {
      // Headers not accessible
    }
  }

  // -------------------------------------------------------------------------
  // Azure Header Analysis
  // -------------------------------------------------------------------------

  private async *analyzeAzureHeaders(
    target: string,
    hostname: string,
  ): AsyncGenerator<Finding> {
    if (!hostname) return;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const response = await fetch(target, {
        method: "HEAD",
        signal: controller.signal,
      });

      clearTimeout(timeout);

      // Check for exposed Azure-specific headers
      const azureHeaders = [
        "x-ms-request-id",
        "x-ms-version",
        "x-ms-client-request-id",
        "x-azure-ref",
      ];

      const exposedHeaders: Array<{ name: string; value: string }> = [];
      for (const header of azureHeaders) {
        const value = response.headers.get(header);
        if (value) {
          exposedHeaders.push({ name: header, value });
        }
      }

      if (exposedHeaders.length > 0) {
        yield this.createFinding(
          "Azure Internal Headers Exposed",
          `The target ${hostname} exposes Azure-internal headers (${exposedHeaders.map((h) => h.name).join(", ")}). These reveal that the application runs on Azure infrastructure and may leak internal request tracking information.`,
          Severity.Info,
          target,
          target,
          "CWE-200",
          0.0,
          80,
          { exposedHeaders },
          "Configure response header removal in the web server or reverse proxy. Use Azure Front Door or Application Gateway rules to strip internal headers.",
        );
      }
    } catch {
      // Headers not accessible
    }
  }

  // -------------------------------------------------------------------------
  // Utility
  // -------------------------------------------------------------------------

  private extractHostname(target: string): string {
    try {
      return new URL(target).hostname;
    } catch {
      let cleaned = target;
      if (cleaned.startsWith("https://")) cleaned = cleaned.slice(8);
      if (cleaned.startsWith("http://")) cleaned = cleaned.slice(7);
      const slashIdx = cleaned.indexOf("/");
      return slashIdx !== -1 ? cleaned.slice(0, slashIdx) : cleaned;
    }
  }

  private createFinding(
    title: string,
    description: string,
    severity: Severity,
    target: string,
    endpoint: string,
    cweId: string,
    cvssScore: number,
    confidence: number,
    extra: Record<string, unknown>,
    remediation: string,
  ): Finding {
    const vulnerability: Vulnerability = {
      id: generateUUID(),
      title,
      description,
      severity,
      category: VulnerabilityCategory.HeaderMisconfig,
      cvssScore,
      cweId,
      target,
      endpoint,
      evidence: { description: title, extra },
      remediation,
      references: [
        `https://cwe.mitre.org/data/definitions/${cweId.replace("CWE-", "")}.html`,
        "https://learn.microsoft.com/en-us/azure/security/",
      ],
      confirmed: severity === Severity.Critical || severity === Severity.High,
      falsePositive: false,
      discoveredAt: new Date().toISOString(),
    };

    return {
      vulnerability,
      module: this.name,
      confidence: Math.max(5, Math.min(95, confidence)),
      timestamp: new Date().toISOString(),
      rawData: extra,
    };
  }
}
