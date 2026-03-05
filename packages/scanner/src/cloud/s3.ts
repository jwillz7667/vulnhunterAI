// =============================================================================
// @vulnhunter/scanner - S3 Bucket Scanner
// =============================================================================
// Specialized scanner for S3 bucket discovery and permission analysis.
// Generates bucket name permutations based on the target, checks ACLs,
// directory listings, and scans for sensitive files in public buckets.
// =============================================================================

import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { generateUUID, createLogger } from "@vulnhunter/core";
import type { ScanModule } from "../engine.js";

const log = createLogger("s3-bucket-scanner");

const REQUEST_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// Sensitive File Patterns
// ---------------------------------------------------------------------------

const SENSITIVE_FILES = [
  { path: ".env", description: "Environment configuration file (may contain secrets)", severity: Severity.Critical },
  { path: ".git/config", description: "Git configuration (may reveal repository URLs)", severity: Severity.High },
  { path: ".git/HEAD", description: "Git HEAD reference", severity: Severity.High },
  { path: "config.json", description: "Application configuration file", severity: Severity.High },
  { path: "config.yml", description: "Application configuration file", severity: Severity.High },
  { path: "database.yml", description: "Database configuration", severity: Severity.Critical },
  { path: "credentials.json", description: "Credentials file", severity: Severity.Critical },
  { path: "credentials.csv", description: "Credentials CSV file", severity: Severity.Critical },
  { path: "secrets.json", description: "Secrets file", severity: Severity.Critical },
  { path: "backup.sql", description: "Database backup", severity: Severity.Critical },
  { path: "dump.sql", description: "Database dump", severity: Severity.Critical },
  { path: "backup.tar.gz", description: "Compressed backup archive", severity: Severity.High },
  { path: "backup.zip", description: "Compressed backup archive", severity: Severity.High },
  { path: "id_rsa", description: "SSH private key", severity: Severity.Critical },
  { path: ".aws/credentials", description: "AWS credentials file", severity: Severity.Critical },
  { path: "terraform.tfstate", description: "Terraform state file (contains secrets)", severity: Severity.Critical },
  { path: "terraform.tfvars", description: "Terraform variables (may contain secrets)", severity: Severity.High },
  { path: ".npmrc", description: "NPM configuration (may contain auth tokens)", severity: Severity.High },
  { path: ".dockercfg", description: "Docker configuration (may contain registry credentials)", severity: Severity.High },
  { path: "wp-config.php", description: "WordPress configuration (database credentials)", severity: Severity.Critical },
  { path: ".htpasswd", description: "Apache password file", severity: Severity.High },
  { path: "private.key", description: "Private key file", severity: Severity.Critical },
  { path: "server.key", description: "TLS server private key", severity: Severity.Critical },
];

// ---------------------------------------------------------------------------
// Bucket Name Permutations
// ---------------------------------------------------------------------------

const PERMUTATION_SUFFIXES = [
  "", "-dev", "-staging", "-stage", "-stg", "-prod", "-production",
  "-backup", "-backups", "-bak", "-data", "-assets", "-static",
  "-media", "-uploads", "-files", "-public", "-private", "-internal",
  "-logs", "-log", "-test", "-testing", "-qa", "-uat",
  "-cdn", "-web", "-api", "-app", "-www",
  "-archive", "-archives", "-old", "-legacy",
  "-db", "-database", "-sql", "-dump",
  "-docs", "-documents", "-reports",
  "-images", "-img", "-photos",
  ".dev", ".staging", ".prod", ".backup",
];

const PERMUTATION_PREFIXES = [
  "", "dev-", "staging-", "prod-", "backup-", "s3-", "aws-",
];

// ---------------------------------------------------------------------------
// S3BucketScanner
// ---------------------------------------------------------------------------

export class S3BucketScanner implements ScanModule {
  readonly name = "cloud:s3";

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    log.info({ target }, "Starting S3 bucket enumeration and analysis");

    const baseName = this.extractBaseName(target);
    const maxPermutations = (options.maxPermutations as number) ?? 100;

    const candidates = this.generateBucketNames(baseName, maxPermutations);
    log.info({ baseName, candidateCount: candidates.length }, "Generated bucket name candidates");

    let bucketsFound = 0;
    let publicBuckets = 0;

    for (const bucketName of candidates) {
      const existsResult = await this.checkBucketExists(bucketName);
      if (!existsResult.exists) continue;

      bucketsFound++;
      log.info({ bucketName, region: existsResult.region }, "S3 bucket found");

      // Check ACL
      yield* this.checkBucketAcl(bucketName, target);

      // Check directory listing
      const isPublicList = await this.checkDirectoryListing(bucketName);
      if (isPublicList) {
        publicBuckets++;

        yield this.createFinding(
          `Public S3 Bucket Directory Listing: ${bucketName}`,
          `The S3 bucket "${bucketName}" allows public directory listing. All objects can be enumerated by anyone on the internet, potentially exposing sensitive files, database backups, credentials, and confidential data.`,
          Severity.High,
          target,
          `https://${bucketName}.s3.amazonaws.com/`,
          "CWE-548",
          7.5,
          95,
          { bucketName, publicListing: true, region: existsResult.region },
          `Disable public access: aws s3api put-public-access-block --bucket ${bucketName} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
        );

        // Check for sensitive files
        yield* this.checkSensitiveFiles(bucketName, target);
      }
    }

    log.info({ target, bucketsFound, publicBuckets, candidatesChecked: candidates.length }, "S3 bucket enumeration complete");
  }

  // -------------------------------------------------------------------------
  // Bucket Discovery
  // -------------------------------------------------------------------------

  private async checkBucketExists(bucketName: string): Promise<{ exists: boolean; region?: string }> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const response = await fetch(`https://${bucketName}.s3.amazonaws.com/`, {
        method: "HEAD",
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (response.status === 200 || response.status === 403 || response.status === 301) {
        const region = response.headers.get("x-amz-bucket-region") ?? undefined;
        return { exists: true, region };
      }

      return { exists: false };
    } catch {
      return { exists: false };
    }
  }

  // -------------------------------------------------------------------------
  // ACL Check
  // -------------------------------------------------------------------------

  private async *checkBucketAcl(bucketName: string, target: string): AsyncGenerator<Finding> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const response = await fetch(`https://${bucketName}.s3.amazonaws.com/?acl`, {
        method: "GET",
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) return;

      const body = await response.text();

      const hasPublicRead = body.includes("AllUsers") && body.includes("READ");
      const hasPublicWrite = body.includes("AllUsers") && body.includes("WRITE");
      const hasAuthRead = body.includes("AuthenticatedUsers") && body.includes("READ");
      const hasFullControl = body.includes("AllUsers") && body.includes("FULL_CONTROL");

      if (hasPublicWrite || hasFullControl) {
        yield this.createFinding(
          `S3 Bucket Public Write Access: ${bucketName}`,
          `The S3 bucket "${bucketName}" grants public WRITE access (or FULL_CONTROL). Anyone on the internet can upload, modify, or delete objects. This enables data tampering, malware distribution, and website defacement.`,
          Severity.Critical,
          target,
          `https://${bucketName}.s3.amazonaws.com/`,
          "CWE-732",
          9.8,
          95,
          { bucketName, publicWrite: hasPublicWrite, fullControl: hasFullControl },
          `Immediately remove public write access: aws s3api put-bucket-acl --bucket ${bucketName} --acl private`,
        );
      }

      if (hasPublicRead) {
        yield this.createFinding(
          `S3 Bucket Public Read Access: ${bucketName}`,
          `The S3 bucket "${bucketName}" grants public READ access via ACL. All objects are accessible to anyone on the internet.`,
          Severity.High,
          target,
          `https://${bucketName}.s3.amazonaws.com/`,
          "CWE-732",
          7.5,
          95,
          { bucketName, publicRead: true },
          `Remove public read access: aws s3api put-bucket-acl --bucket ${bucketName} --acl private`,
        );
      }

      if (hasAuthRead) {
        yield this.createFinding(
          `S3 Bucket Authenticated Read: ${bucketName}`,
          `The S3 bucket "${bucketName}" grants READ access to any authenticated AWS user (AuthenticatedUsers). Any user with any AWS account can access the bucket contents.`,
          Severity.High,
          target,
          `https://${bucketName}.s3.amazonaws.com/`,
          "CWE-732",
          7.5,
          90,
          { bucketName, authenticatedRead: true },
          `Remove the AuthenticatedUsers grant. Use bucket policies with specific principal ARNs instead.`,
        );
      }
    } catch {
      // ACL not accessible
    }
  }

  // -------------------------------------------------------------------------
  // Directory Listing
  // -------------------------------------------------------------------------

  private async checkDirectoryListing(bucketName: string): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const response = await fetch(`https://${bucketName}.s3.amazonaws.com/`, {
        method: "GET",
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) return false;

      const body = await response.text();
      return body.includes("<ListBucketResult") || body.includes("<Contents>");
    } catch {
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // Sensitive File Detection
  // -------------------------------------------------------------------------

  private async *checkSensitiveFiles(bucketName: string, target: string): AsyncGenerator<Finding> {
    for (const sensitiveFile of SENSITIVE_FILES) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const fileUrl = `https://${bucketName}.s3.amazonaws.com/${sensitiveFile.path}`;
        const response = await fetch(fileUrl, {
          method: "HEAD",
          signal: controller.signal,
        });

        clearTimeout(timeout);

        if (response.ok) {
          const contentLength = response.headers.get("content-length") ?? "unknown";

          yield this.createFinding(
            `Sensitive File Exposed: ${sensitiveFile.path} in ${bucketName}`,
            `The file "${sensitiveFile.path}" is publicly accessible in S3 bucket "${bucketName}". ${sensitiveFile.description}. File size: ${contentLength} bytes.`,
            sensitiveFile.severity,
            target,
            fileUrl,
            "CWE-538",
            sensitiveFile.severity === Severity.Critical ? 9.1 : sensitiveFile.severity === Severity.High ? 7.5 : 5.3,
            90,
            {
              bucketName,
              filePath: sensitiveFile.path,
              fileSize: contentLength,
              contentType: response.headers.get("content-type"),
            },
            `Remove "${sensitiveFile.path}" from the public bucket or restrict access. If the file contains secrets, rotate all exposed credentials immediately.`,
          );
        }
      } catch {
        // File not accessible
      }
    }
  }

  // -------------------------------------------------------------------------
  // Bucket Name Generation
  // -------------------------------------------------------------------------

  private generateBucketNames(baseName: string, maxCount: number): string[] {
    const candidates = new Set<string>();

    candidates.add(baseName);

    for (const suffix of PERMUTATION_SUFFIXES) {
      if (candidates.size >= maxCount) break;
      const name = `${baseName}${suffix}`;
      if (this.isValidBucketName(name)) candidates.add(name);
    }

    for (const prefix of PERMUTATION_PREFIXES) {
      if (candidates.size >= maxCount) break;
      const name = `${prefix}${baseName}`;
      if (this.isValidBucketName(name)) candidates.add(name);
    }

    for (const prefix of PERMUTATION_PREFIXES) {
      for (const suffix of PERMUTATION_SUFFIXES.slice(0, 10)) {
        if (candidates.size >= maxCount) break;
        const name = `${prefix}${baseName}${suffix}`;
        if (this.isValidBucketName(name)) candidates.add(name);
      }
    }

    return [...candidates].slice(0, maxCount);
  }

  private extractBaseName(target: string): string {
    let name = target;
    if (name.startsWith("https://")) name = name.slice(8);
    if (name.startsWith("http://")) name = name.slice(7);
    const slashIdx = name.indexOf("/");
    if (slashIdx !== -1) name = name.slice(0, slashIdx);
    const colonIdx = name.lastIndexOf(":");
    if (colonIdx !== -1) name = name.slice(0, colonIdx);

    const parts = name.split(".");
    if (parts.length >= 2) {
      const filtered = parts.filter(
        (p) => !["www", "com", "org", "net", "io", "co", "dev", "app"].includes(p),
      );
      name = filtered.join("-") || parts[0];
    }

    return name
      .toLowerCase()
      .replace(/[^a-z0-9.-]/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "");
  }

  private isValidBucketName(name: string): boolean {
    if (name.length < 3 || name.length > 63) return false;
    if (!/^[a-z0-9]/.test(name)) return false;
    if (!/[a-z0-9]$/.test(name)) return false;
    if (name.includes("..") || name.includes("-.") || name.includes(".-")) return false;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(name)) return false;
    return true;
  }

  // -------------------------------------------------------------------------
  // Utility
  // -------------------------------------------------------------------------

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
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore,
      cweId,
      target,
      endpoint,
      evidence: { description: title, extra },
      remediation,
      references: [
        `https://cwe.mitre.org/data/definitions/${cweId.replace("CWE-", "")}.html`,
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
      ],
      confirmed: true,
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
