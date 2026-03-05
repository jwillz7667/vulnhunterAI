// =============================================================================
// @vulnhunter/scanner - GCP Misconfiguration Scanner
// =============================================================================
// Detects common GCP misconfigurations including publicly accessible GCS
// buckets, exposed metadata endpoints (metadata.google.internal), service
// account key exposure, and open Firebase/Firestore databases.
// =============================================================================

import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { generateUUID, createLogger } from "@vulnhunter/core";
import type { ScanModule } from "../engine.js";

const log = createLogger("gcp-scanner");

const REQUEST_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// GCS Bucket Name Extraction Patterns
// ---------------------------------------------------------------------------

const GCS_PATTERNS = [
  // storage.googleapis.com/bucket
  /storage\.googleapis\.com\/([a-z0-9][a-z0-9._-]{1,221}[a-z0-9])/i,
  // bucket.storage.googleapis.com
  /([a-z0-9][a-z0-9._-]{1,221}[a-z0-9])\.storage\.googleapis\.com/i,
  // storage.cloud.google.com/bucket
  /storage\.cloud\.google\.com\/([a-z0-9][a-z0-9._-]{1,221}[a-z0-9])/i,
];

// ---------------------------------------------------------------------------
// GcpScanner
// ---------------------------------------------------------------------------

export class GcpScanner implements ScanModule {
  readonly name = "cloud:gcp";

  async *execute(
    target: string,
    _options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const hostname = this.extractHostname(target);

    log.info({ target, hostname }, "Starting GCP misconfiguration scan");

    // 1. GCS Bucket Enumeration from URL
    yield* this.detectGcsFromUrl(target);

    // 2. GCS Bucket Permutation (based on target hostname)
    yield* this.enumerateBucketPermutations(target, hostname);

    // 3. Metadata Endpoint Exposure
    yield* this.checkMetadataEndpoint(target, hostname);

    // 4. Service Account Key Exposure
    yield* this.checkServiceAccountKeyExposure(target);

    // 5. Firebase / Firestore Open Database
    yield* this.checkFirebaseExposure(target, hostname);

    log.info({ target }, "GCP misconfiguration scan complete");
  }

  // -------------------------------------------------------------------------
  // GCS Bucket Detection from URL
  // -------------------------------------------------------------------------

  private async *detectGcsFromUrl(target: string): AsyncGenerator<Finding> {
    for (const pattern of GCS_PATTERNS) {
      const match = target.match(pattern);
      if (!match) continue;

      const bucketName = match[1];
      log.info({ bucketName }, "GCS bucket detected in target URL");
      yield* this.checkBucketPermissions(bucketName, target);
    }
  }

  // -------------------------------------------------------------------------
  // GCS Bucket Permutation Enumeration
  // -------------------------------------------------------------------------

  private async *enumerateBucketPermutations(
    target: string,
    hostname: string,
  ): AsyncGenerator<Finding> {
    if (!hostname) return;

    const baseName = hostname.replace(/\.[^.]+$/, "").replace(/\./g, "-");
    const suffixes = [
      "", "-dev", "-staging", "-prod", "-production", "-backup", "-backups",
      "-data", "-assets", "-static", "-media", "-uploads", "-logs",
      "-private", "-public", "-internal", "-test", "-tmp",
    ];

    for (const suffix of suffixes) {
      const bucketName = `${baseName}${suffix}`;

      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const response = await fetch(
          `https://storage.googleapis.com/${bucketName}`,
          { method: "GET", signal: controller.signal, redirect: "follow" },
        );

        clearTimeout(timeout);

        if (response.ok) {
          const body = await response.text();
          if (body.includes("<ListBucketResult") || body.includes("<Contents>") || body.includes("<Key>")) {
            yield this.createFinding(
              `Public GCS Bucket Discovered: ${bucketName}`,
              `The Google Cloud Storage bucket "${bucketName}" allows public listing. An attacker can enumerate all objects in this bucket, potentially exposing sensitive data, configuration files, database backups, and credentials.`,
              Severity.High,
              target,
              `https://storage.googleapis.com/${bucketName}`,
              "CWE-284",
              7.5,
              90,
              { bucketName, publicListing: true },
              "Remove public access from the GCS bucket. Use Uniform bucket-level access and set allUsers/allAuthenticatedUsers to have no roles. Enable GCP Organization Policy to prevent public bucket creation.",
            );
          }
        }
      } catch {
        // Bucket does not exist or is not accessible
      }

      // Test for public write
      try {
        const testKey = `vulnhunter-gcs-test-${Date.now()}.txt`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const response = await fetch(
          `https://storage.googleapis.com/upload/storage/v1/b/${bucketName}/o?uploadType=media&name=${testKey}`,
          {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: "vulnhunter-security-test",
            signal: controller.signal,
          },
        );

        clearTimeout(timeout);

        if (response.ok) {
          yield this.createFinding(
            `Public Write Access to GCS Bucket: ${bucketName}`,
            `The GCS bucket "${bucketName}" allows public write access. An attacker can upload malicious content, overwrite existing files, or use the bucket for data exfiltration.`,
            Severity.Critical,
            target,
            `https://storage.googleapis.com/${bucketName}`,
            "CWE-284",
            9.8,
            95,
            { bucketName, publicWrite: true },
            "Immediately revoke public write access. Use Uniform bucket-level access. Enable GCP Organization Policy constraints to block public bucket access.",
          );

          // Cleanup
          try {
            await fetch(
              `https://storage.googleapis.com/storage/v1/b/${bucketName}/o/${testKey}`,
              { method: "DELETE" },
            );
          } catch {
            // Cleanup failure is acceptable
          }
        }
      } catch {
        // Expected for non-writable buckets
      }
    }
  }

  // -------------------------------------------------------------------------
  // Bucket Permission Check
  // -------------------------------------------------------------------------

  private async *checkBucketPermissions(
    bucketName: string,
    target: string,
  ): AsyncGenerator<Finding> {
    // Test for public listing
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const response = await fetch(
        `https://storage.googleapis.com/storage/v1/b/${bucketName}/o?maxResults=5`,
        { method: "GET", signal: controller.signal },
      );

      clearTimeout(timeout);

      if (response.ok) {
        const body = await response.text();
        if (body.includes('"items"') || body.includes('"kind"')) {
          yield this.createFinding(
            `Public GCS Bucket: ${bucketName}`,
            `The GCS bucket "${bucketName}" allows public object listing via the JSON API. All objects can be enumerated and potentially downloaded by any unauthenticated user.`,
            Severity.High,
            target,
            `https://storage.googleapis.com/storage/v1/b/${bucketName}/o`,
            "CWE-284",
            7.5,
            95,
            { bucketName, publicListing: true },
            "Remove allUsers and allAuthenticatedUsers IAM bindings from the bucket. Enable Uniform bucket-level access. Use GCP Organization Policy to enforce private buckets.",
          );
        }
      }
    } catch {
      // Not accessible
    }

    // Test for public IAM policy read
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const response = await fetch(
        `https://storage.googleapis.com/storage/v1/b/${bucketName}/iam`,
        { method: "GET", signal: controller.signal },
      );

      clearTimeout(timeout);

      if (response.ok) {
        const body = await response.text();
        if (body.includes("allUsers") || body.includes("allAuthenticatedUsers")) {
          yield this.createFinding(
            `GCS Bucket IAM Policy Publicly Readable: ${bucketName}`,
            `The IAM policy for GCS bucket "${bucketName}" is publicly readable and reveals public bindings (allUsers or allAuthenticatedUsers). This confirms the bucket has overly permissive access controls.`,
            Severity.Medium,
            target,
            `https://storage.googleapis.com/storage/v1/b/${bucketName}/iam`,
            "CWE-284",
            5.3,
            90,
            { bucketName, iamPubliclyReadable: true },
            "Remove public IAM bindings. Set the bucket to Uniform access mode and remove allUsers/allAuthenticatedUsers members.",
          );
        }
      }
    } catch {
      // Not accessible
    }
  }

  // -------------------------------------------------------------------------
  // Metadata Endpoint Check
  // -------------------------------------------------------------------------

  private async *checkMetadataEndpoint(
    target: string,
    hostname: string,
  ): AsyncGenerator<Finding> {
    const metadataUrls = [
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      "http://metadata.google.internal/computeMetadata/v1/project/project-id",
      "http://metadata.google.internal/computeMetadata/v1/instance/zone",
      "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
    ];

    for (const metaUrl of metadataUrls) {
      // Direct access test
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const response = await fetch(metaUrl, {
          method: "GET",
          headers: { "Metadata-Flavor": "Google" },
          signal: controller.signal,
          redirect: "manual",
        });

        clearTimeout(timeout);

        if (response.ok) {
          const body = await response.text();

          if (
            body.includes("access_token") ||
            body.includes("project") ||
            body.includes("instance") ||
            body.includes("service-accounts") ||
            body.includes("zones/")
          ) {
            yield this.createFinding(
              "GCP Instance Metadata Endpoint Accessible",
              `The GCP metadata endpoint at ${metaUrl} is directly accessible. This exposes instance identity, service account tokens, project metadata, and custom attributes. An attacker can use the service account token to access GCP APIs with the instance's permissions.`,
              Severity.Critical,
              target,
              metaUrl,
              "CWE-918",
              9.8,
              95,
              { metadataUrl: metaUrl, responseSnippet: body.slice(0, 500) },
              "Use GKE Workload Identity instead of node-level service accounts. Implement network policies to block metadata access from application pods. Use the Metadata-Flavor header validation. Restrict service account permissions following least privilege.",
            );
          }
        }
      } catch {
        // Not accessible, which is expected
      }
    }

    // SSRF-based metadata test via target application
    if (hostname) {
      const ssrfPayloads = [
        `${target.replace(/\/$/, "")}/?url=http://metadata.google.internal/computeMetadata/v1/`,
        `${target.replace(/\/$/, "")}/?redirect=http://metadata.google.internal/computeMetadata/v1/`,
      ];

      for (const ssrfUrl of ssrfPayloads) {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

          const response = await fetch(ssrfUrl, {
            signal: controller.signal,
            redirect: "follow",
          });

          clearTimeout(timeout);

          if (response.ok) {
            const body = await response.text();
            if (body.includes("project") || body.includes("instance") || body.includes("access_token")) {
              yield this.createFinding(
                "SSRF to GCP Metadata Service via Target Application",
                `The target application at ${hostname} appears to proxy requests to the GCP metadata endpoint. This SSRF vulnerability allows an attacker to steal service account tokens and access GCP resources.`,
                Severity.Critical,
                target,
                ssrfUrl,
                "CWE-918",
                9.8,
                85,
                { ssrfUrl, responseContainsMetadata: true },
                "Fix the SSRF vulnerability. Block outbound requests to metadata.google.internal. Use Workload Identity for GKE. Restrict service account permissions.",
              );
            }
          }
        } catch {
          // Expected failure
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Service Account Key Exposure
  // -------------------------------------------------------------------------

  private async *checkServiceAccountKeyExposure(
    target: string,
  ): AsyncGenerator<Finding> {
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

      // Check for GCP service account key JSON patterns
      const saKeyPatterns = [
        /"type"\s*:\s*"service_account"/i,
        /"project_id"\s*:\s*"[a-z][a-z0-9-]{4,28}[a-z0-9]"/i,
        /"private_key_id"\s*:\s*"[a-f0-9]{40}"/i,
        /"private_key"\s*:\s*"-----BEGIN (RSA )?PRIVATE KEY-----/i,
        /"client_email"\s*:\s*"[^"]+@[^"]+\.iam\.gserviceaccount\.com"/i,
      ];

      let matchCount = 0;
      const matchedPatterns: string[] = [];
      for (const pattern of saKeyPatterns) {
        if (pattern.test(body)) {
          matchCount++;
          matchedPatterns.push(pattern.source);
        }
      }

      // Require at least 3 patterns to match to reduce false positives
      if (matchCount >= 3) {
        yield this.createFinding(
          "GCP Service Account Key Exposed",
          `The target exposes what appears to be a GCP service account key JSON file. This contains a private key that grants the service account's full permissions to GCP APIs. Matched ${matchCount}/5 service account key indicators.`,
          Severity.Critical,
          target,
          target,
          "CWE-798",
          9.8,
          90,
          { matchCount, matchedPatterns },
          "Immediately rotate the exposed service account key. Delete the compromised key from the GCP Console. Audit recent API activity for the service account. Use Workload Identity or metadata-based credentials instead of key files. Store secrets in Secret Manager, not in application code or public locations.",
        );
      }

      // Check for individual credential-like patterns
      const clientEmailMatch = body.match(
        /[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com/gi,
      );
      if (clientEmailMatch) {
        const uniqueEmails = [...new Set(clientEmailMatch)];
        yield this.createFinding(
          "GCP Service Account Email Exposed",
          `The target exposes ${uniqueEmails.length} GCP service account email(s): ${uniqueEmails.slice(0, 3).join(", ")}. While the email alone is not sufficient for authentication, it reveals internal GCP project structure and service account names that aid in targeted attacks.`,
          Severity.Low,
          target,
          target,
          "CWE-200",
          3.7,
          80,
          { serviceAccountEmails: uniqueEmails },
          "Remove service account emails from public-facing content. Use environment variables or Secret Manager for service account configuration.",
        );
      }
    } catch {
      // Network error
    }
  }

  // -------------------------------------------------------------------------
  // Firebase / Firestore Exposure
  // -------------------------------------------------------------------------

  private async *checkFirebaseExposure(
    target: string,
    hostname: string,
  ): AsyncGenerator<Finding> {
    if (!hostname) return;

    // Derive potential Firebase project names from the hostname
    const baseName = hostname.replace(/\.[^.]+$/, "").replace(/\./g, "-");
    const projectNames = [baseName, `${baseName}-default-rtdb`];

    for (const project of projectNames) {
      // Test Firebase Realtime Database
      try {
        const fbUrl = `https://${project}.firebaseio.com/.json`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const response = await fetch(fbUrl, {
          signal: controller.signal,
          redirect: "follow",
        });

        clearTimeout(timeout);

        if (response.ok) {
          const body = await response.text();
          if (body !== "null" && body.length > 2) {
            yield this.createFinding(
              `Open Firebase Realtime Database: ${project}`,
              `The Firebase Realtime Database at ${fbUrl} is publicly readable without authentication. Database contents are exposed to any unauthenticated user, potentially including user data, application state, and sensitive configuration.`,
              Severity.High,
              target,
              fbUrl,
              "CWE-284",
              7.5,
              90,
              { projectName: project, databaseUrl: fbUrl, responseSize: body.length },
              "Update Firebase Security Rules to require authentication for all reads and writes. Use Firebase Authentication to control access. Audit the database for sensitive data exposure.",
            );
          }
        }
      } catch {
        // Not accessible
      }

      // Test Firestore REST API
      try {
        const fsUrl = `https://firestore.googleapis.com/v1/projects/${project}/databases/(default)/documents`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

        const response = await fetch(fsUrl, {
          signal: controller.signal,
          redirect: "follow",
        });

        clearTimeout(timeout);

        if (response.ok) {
          const body = await response.text();
          if (body.includes('"documents"') || body.includes('"name"')) {
            yield this.createFinding(
              `Open Firestore Database: ${project}`,
              `The Firestore database for project "${project}" is publicly accessible. Collections and documents can be read without authentication via the REST API.`,
              Severity.High,
              target,
              fsUrl,
              "CWE-284",
              7.5,
              85,
              { projectName: project, firestoreUrl: fsUrl },
              "Update Firestore Security Rules to require authentication. Review all collection-level rules. Use Firebase Authentication to control access.",
            );
          }
        }
      } catch {
        // Not accessible
      }
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
        "https://cloud.google.com/security/best-practices",
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
