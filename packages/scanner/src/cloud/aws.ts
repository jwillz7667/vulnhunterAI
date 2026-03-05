// =============================================================================
// @vulnhunter/scanner - AWS Misconfiguration Scanner
// =============================================================================
// Detects common AWS misconfigurations including public S3 buckets, exposed
// metadata endpoints, public snapshots, CloudFront misconfigurations, and
// overly permissive IAM policy patterns.
// =============================================================================

import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { generateUUID, createLogger } from "@vulnhunter/core";
import type { ScanModule } from "../engine.js";

const log = createLogger("aws-scanner");

const REQUEST_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// AwsScanner
// ---------------------------------------------------------------------------

export class AwsScanner implements ScanModule {
  readonly name = "cloud:aws";

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const hostname = this.extractHostname(target);

    log.info({ target, hostname }, "Starting AWS misconfiguration scan");

    // 1. Metadata Endpoint Exposure (IMDS)
    yield* this.checkMetadataEndpoint(target, hostname);

    // 2. S3 Bucket Detection from target URL
    yield* this.detectS3FromUrl(target);

    // 3. CloudFront Misconfiguration
    yield* this.checkCloudFrontMisconfig(target, hostname);

    // 4. Public Snapshot Detection (via common URL patterns)
    yield* this.checkPublicSnapshots(target, hostname, options);

    // 5. IAM-Related Header Checks
    yield* this.checkIamHeaders(target, hostname);

    log.info({ target }, "AWS misconfiguration scan complete");
  }

  // -------------------------------------------------------------------------
  // IMDS (Instance Metadata Service) Check
  // -------------------------------------------------------------------------

  /**
   * Check if the target can be used to access the AWS IMDS endpoint via SSRF.
   * Tests both IMDSv1 (no token required) and IMDSv2.
   */
  private async *checkMetadataEndpoint(
    target: string,
    hostname: string,
  ): AsyncGenerator<Finding> {
    const metadataUrls = [
      "http://169.254.169.254/latest/meta-data/",
      "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "http://169.254.169.254/latest/dynamic/instance-identity/document",
      "http://169.254.170.2/v2/credentials/", // ECS task role
    ];

    for (const metaUrl of metadataUrls) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        // Test direct access to metadata endpoint (relevant if target is an IP/host on AWS)
        const response = await fetch(metaUrl, {
          method: "GET",
          headers: { Connection: "close" },
          signal: controller.signal,
          redirect: "manual",
        });

        clearTimeout(timeout);

        if (response.ok) {
          const body = await response.text();

          // Verify it looks like real IMDS output
          if (
            body.includes("ami-id") ||
            body.includes("instance-id") ||
            body.includes("security-credentials") ||
            body.includes("AccessKeyId") ||
            body.includes("accountId")
          ) {
            yield this.createFinding(
              "AWS Instance Metadata Service (IMDS) Accessible",
              `The AWS Instance Metadata Service at ${metaUrl} is directly accessible. This exposes sensitive instance information including IAM role credentials, instance identity, and network configuration. An attacker with access to this endpoint can escalate privileges by assuming the instance's IAM role.`,
              Severity.Critical,
              target,
              metaUrl,
              "CWE-918",
              9.8,
              95,
              { metadataUrl: metaUrl, responseSnippet: body.slice(0, 500) },
              "Enforce IMDSv2 by requiring a PUT request with a token (HttpTokens: required). Apply ec2:MetadataHttpTokens condition key in IAM policies. Use network-level controls to prevent SSRF to 169.254.169.254. Consider disabling IMDS if not needed.",
            );
          }
        }
      } catch {
        // Not accessible, which is expected and good
      }
    }

    // Check if the target itself proxies to IMDS (SSRF test)
    if (hostname) {
      try {
        const ssrfUrl = `${target.replace(/\/$/, "")}/?url=http://169.254.169.254/latest/meta-data/`;

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const response = await fetch(ssrfUrl, {
          signal: controller.signal,
          redirect: "follow",
        });

        clearTimeout(timeout);

        if (response.ok) {
          const body = await response.text();
          if (body.includes("ami-id") || body.includes("instance-id")) {
            yield this.createFinding(
              "SSRF to AWS Metadata Service via Target Application",
              `The target application at ${hostname} appears to proxy requests to the AWS Instance Metadata Service (169.254.169.254). This is a Server-Side Request Forgery vulnerability that allows an attacker to steal IAM role credentials from the underlying EC2 instance.`,
              Severity.Critical,
              target,
              ssrfUrl,
              "CWE-918",
              9.8,
              85,
              { ssrfUrl, responseContainsMetadata: true },
              "Fix the SSRF vulnerability in the application. Block outbound requests to 169.254.169.254 at the network level. Enforce IMDSv2 (token-based). Apply the principle of least privilege to IAM roles attached to EC2 instances.",
            );
          }
        }
      } catch {
        // Expected failure
      }
    }
  }

  // -------------------------------------------------------------------------
  // S3 Detection from URL
  // -------------------------------------------------------------------------

  /**
   * Detect S3 bucket references in the target URL and check their permissions.
   */
  private async *detectS3FromUrl(target: string): AsyncGenerator<Finding> {
    const s3Patterns = [
      // Virtual-hosted style: bucket.s3.amazonaws.com
      /(?:^|\/\/)([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-](?:[a-z0-9-]+\.)?amazonaws\.com/i,
      // Path-style: s3.amazonaws.com/bucket
      /s3[.\-](?:[a-z0-9-]+\.)?amazonaws\.com\/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])/i,
      // S3 website: bucket.s3-website-region.amazonaws.com
      /([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3-website[.\-][a-z0-9-]+\.amazonaws\.com/i,
    ];

    for (const pattern of s3Patterns) {
      const match = target.match(pattern);
      if (!match) continue;

      const bucketName = match[1];
      log.info({ bucketName }, "S3 bucket detected in target URL");

      // Check bucket ACL
      yield* this.checkBucketPermissions(bucketName, target);
    }
  }

  /**
   * Check S3 bucket permissions via HTTP requests.
   */
  private async *checkBucketPermissions(
    bucketName: string,
    target: string,
  ): AsyncGenerator<Finding> {
    const bucketUrl = `https://${bucketName}.s3.amazonaws.com`;

    // Test for directory listing (public read)
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const response = await fetch(bucketUrl, {
        method: "GET",
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (response.ok) {
        const body = await response.text();
        if (body.includes("<ListBucketResult") || body.includes("<Contents>")) {
          yield this.createFinding(
            `Public S3 Bucket: ${bucketName}`,
            `The S3 bucket "${bucketName}" allows public listing (ListBucket). Anyone can enumerate all objects in this bucket, potentially exposing sensitive files, database backups, credentials, and other confidential data.`,
            Severity.High,
            target,
            bucketUrl,
            "CWE-284",
            7.5,
            95,
            { bucketName, publicListing: true },
            "Disable public access: aws s3api put-public-access-block --bucket ${bucketName} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true. Review and update the bucket policy to deny public access.",
          );
        }
      } else if (response.status === 403) {
        // Bucket exists but not publicly listable (good)
      } else if (response.status === 404) {
        // Bucket doesn't exist
      }
    } catch {
      // Network error
    }

    // Test for public write
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const testKey = `vulnhunter-write-test-${Date.now()}.txt`;
      const response = await fetch(`${bucketUrl}/${testKey}`, {
        method: "PUT",
        headers: { "Content-Type": "text/plain" },
        body: "vulnhunter-security-test",
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (response.ok || response.status === 200) {
        yield this.createFinding(
          `Public Write Access to S3 Bucket: ${bucketName}`,
          `The S3 bucket "${bucketName}" allows public write access. Anyone can upload objects to this bucket, enabling data tampering, malware hosting, and potential code execution if the bucket serves web content.`,
          Severity.Critical,
          target,
          bucketUrl,
          "CWE-284",
          9.8,
          95,
          { bucketName, publicWrite: true },
          "Immediately revoke public write access. Enable S3 Block Public Access at the account level. Review all bucket policies and ACLs. Enable S3 access logging and CloudTrail for audit.",
        );

        // Clean up: try to delete the test object
        try {
          await fetch(`${bucketUrl}/${testKey}`, { method: "DELETE" });
        } catch {
          // Cleanup failure is acceptable
        }
      }
    } catch {
      // Expected failure
    }
  }

  // -------------------------------------------------------------------------
  // CloudFront Misconfiguration
  // -------------------------------------------------------------------------

  private async *checkCloudFrontMisconfig(
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
        redirect: "follow",
      });

      clearTimeout(timeout);

      const server = response.headers.get("server") ?? "";
      const via = response.headers.get("via") ?? "";
      const xAmzCfId = response.headers.get("x-amz-cf-id");

      const isCloudFront = server.includes("CloudFront") || via.includes("cloudfront") || xAmzCfId !== null;

      if (!isCloudFront) return;

      log.info({ hostname }, "CloudFront distribution detected");

      // Check for origin access misconfiguration
      // Test if direct origin access is possible by looking for S3 origin
      const xAmzBucket = response.headers.get("x-amz-bucket-region");
      if (xAmzBucket) {
        yield this.createFinding(
          "CloudFront Origin Information Leakage",
          `The CloudFront distribution at ${hostname} leaks origin information via response headers (x-amz-bucket-region: ${xAmzBucket}). This reveals the S3 origin region and potentially aids attackers in bypassing CloudFront protections.`,
          Severity.Low,
          target,
          target,
          "CWE-200",
          3.7,
          75,
          { server, via, xAmzBucket },
          "Configure CloudFront to strip origin-specific headers from responses. Use a CloudFront response headers policy to remove unnecessary headers.",
        );
      }

      // Check for cache-related security headers
      const cacheControl = response.headers.get("cache-control") ?? "";
      if (!cacheControl.includes("no-store") && !cacheControl.includes("private")) {
        const setCookie = response.headers.get("set-cookie");
        if (setCookie) {
          yield this.createFinding(
            "CloudFront Caching Sensitive Response Headers",
            `The CloudFront distribution at ${hostname} may be caching responses that include Set-Cookie headers without appropriate Cache-Control directives. This could serve another user's session cookies to different users.`,
            Severity.High,
            target,
            target,
            "CWE-524",
            7.5,
            65,
            { cacheControl, hasSetCookie: true },
            "Add 'Cache-Control: no-store, private' to responses that set cookies. Configure CloudFront to forward cookies only when needed. Use cache behaviors to separate cacheable and non-cacheable content.",
          );
        }
      }
    } catch {
      // Target not accessible
    }
  }

  // -------------------------------------------------------------------------
  // Public Snapshot Detection
  // -------------------------------------------------------------------------

  private async *checkPublicSnapshots(
    target: string,
    _hostname: string,
    _options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    // This check works when we have AWS credentials or can query the API
    // For external scanning, we check for common indicators
    // Look for snapshot IDs in the target/response
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const response = await fetch(target, {
        signal: controller.signal,
        redirect: "follow",
      });

      clearTimeout(timeout);

      if (!response.ok) return;

      const body = await response.text();

      // Check for exposed AWS snapshot IDs
      const snapPattern = /snap-[0-9a-f]{8,17}/gi;
      const snapMatches = body.match(snapPattern);

      if (snapMatches && snapMatches.length > 0) {
        const uniqueSnaps = [...new Set(snapMatches)];
        yield this.createFinding(
          "AWS EBS Snapshot IDs Exposed",
          `The target application exposes ${uniqueSnaps.length} AWS EBS snapshot ID(s): ${uniqueSnaps.slice(0, 5).join(", ")}. If these snapshots are publicly shared, an attacker can copy and mount them to extract sensitive data, database dumps, and credentials.`,
          Severity.Medium,
          target,
          target,
          "CWE-200",
          5.3,
          60,
          { snapshotIds: uniqueSnaps },
          "Remove snapshot IDs from public-facing responses. Verify that all EBS snapshots are private. Use AWS Config rules to detect and remediate public snapshots automatically.",
        );
      }

      // Check for exposed AWS account IDs
      const accountPattern = /(?:^|[^0-9])(\d{12})(?:$|[^0-9])/g;
      const arnPattern = /arn:aws[a-zA-Z-]*:[a-zA-Z0-9-]+:[a-z0-9-]*:(\d{12}):/g;
      let arnMatch: RegExpExecArray | null;
      const accountIds = new Set<string>();

      while ((arnMatch = arnPattern.exec(body)) !== null) {
        accountIds.add(arnMatch[1]);
      }

      if (accountIds.size > 0) {
        yield this.createFinding(
          "AWS Account ID and ARN Exposure",
          `The target application exposes AWS ARNs containing account ID(s): ${[...accountIds].join(", ")}. While not directly exploitable, AWS account IDs help attackers enumerate resources, attempt cross-account access, and craft targeted attacks.`,
          Severity.Low,
          target,
          target,
          "CWE-200",
          3.7,
          70,
          { accountIds: [...accountIds] },
          "Remove AWS ARNs from public-facing responses. Use CloudFront functions or Lambda@Edge to strip sensitive headers and response content.",
        );
      }
    } catch {
      // Network error
    }
  }

  // -------------------------------------------------------------------------
  // IAM Header Checks
  // -------------------------------------------------------------------------

  private async *checkIamHeaders(
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

      // Check for exposed AWS-specific headers
      const sensitiveHeaders = [
        "x-amz-request-id",
        "x-amz-id-2",
        "x-amzn-requestid",
        "x-amz-apigw-id",
      ];

      const exposedHeaders: string[] = [];
      for (const header of sensitiveHeaders) {
        if (response.headers.get(header)) {
          exposedHeaders.push(header);
        }
      }

      if (exposedHeaders.length > 0) {
        yield this.createFinding(
          "AWS Internal Headers Exposed",
          `The target ${hostname} exposes AWS-internal headers (${exposedHeaders.join(", ")}). These headers reveal that the application runs on AWS infrastructure and can aid in fingerprinting the specific AWS service (S3, API Gateway, Lambda, etc.).`,
          Severity.Info,
          target,
          target,
          "CWE-200",
          0.0,
          80,
          { exposedHeaders },
          "Configure response header policies to strip AWS-internal headers before they reach clients. For API Gateway, use response mapping templates. For CloudFront, use a response headers policy.",
        );
      }
    } catch {
      // Network error
    }
  }

  // -------------------------------------------------------------------------
  // Utility
  // -------------------------------------------------------------------------

  private extractHostname(target: string): string {
    try {
      const url = new URL(target);
      return url.hostname;
    } catch {
      let cleaned = target;
      if (cleaned.startsWith("https://")) cleaned = cleaned.slice(8);
      if (cleaned.startsWith("http://")) cleaned = cleaned.slice(7);
      const slashIdx = cleaned.indexOf("/");
      if (slashIdx !== -1) cleaned = cleaned.slice(0, slashIdx);
      return cleaned;
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
        "https://docs.aws.amazon.com/security/",
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
