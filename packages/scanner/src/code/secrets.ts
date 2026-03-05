// =============================================================================
// @vulnhunter/scanner - Secret Detection Scanner
// =============================================================================
// Scans source code directories for leaked secrets, API keys, tokens, and
// credentials using regex patterns and Shannon entropy analysis. Respects
// .gitignore rules and skips binary files.
// =============================================================================

import { readdir, readFile, stat, access } from "node:fs/promises";
import { join, extname, relative, dirname } from "node:path";
import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { generateUUID, createLogger } from "@vulnhunter/core";
import type { ScanModule } from "../engine.js";

const log = createLogger("secret-scanner");

// ---------------------------------------------------------------------------
// Secret Pattern Definitions
// ---------------------------------------------------------------------------

interface SecretPattern {
  /** Unique identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Detection regex */
  pattern: RegExp;
  /** Severity level of this secret type */
  severity: Severity;
  /** Brief description of the secret type */
  description: string;
  /** Confidence boost/penalty for this pattern (added to base 70) */
  confidenceModifier: number;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // --- AWS ---
  {
    id: "aws-access-key",
    name: "AWS Access Key ID",
    pattern: /(?:^|['"=\s:])(?<key>AKIA[0-9A-Z]{16})(?:['";\s,\n]|$)/gm,
    severity: Severity.Critical,
    description:
      "AWS Access Key ID detected. These credentials grant programmatic access to AWS resources and can lead to full account compromise.",
    confidenceModifier: 20,
  },
  {
    id: "aws-secret-key",
    name: "AWS Secret Access Key",
    pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key|AWS_SECRET)\s*[=:]\s*['"]?(?<key>[A-Za-z0-9/+=]{40})['"]?/gi,
    severity: Severity.Critical,
    description:
      "AWS Secret Access Key detected. Combined with an Access Key ID, this provides full programmatic access to AWS services.",
    confidenceModifier: 20,
  },
  // --- GitHub ---
  {
    id: "github-pat",
    name: "GitHub Personal Access Token",
    pattern: /(?:^|['"=\s:])(?<key>ghp_[A-Za-z0-9_]{36,})(?:['";\s,\n]|$)/gm,
    severity: Severity.Critical,
    description:
      "GitHub Personal Access Token (ghp_) detected. This token grants access to GitHub repositories, organizations, and user data.",
    confidenceModifier: 20,
  },
  {
    id: "github-oauth",
    name: "GitHub OAuth Access Token",
    pattern: /(?:^|['"=\s:])(?<key>gho_[A-Za-z0-9_]{36,})(?:['";\s,\n]|$)/gm,
    severity: Severity.Critical,
    description:
      "GitHub OAuth Access Token (gho_) detected. This token grants delegated access to GitHub resources.",
    confidenceModifier: 20,
  },
  {
    id: "github-user-to-server",
    name: "GitHub User-to-Server Token",
    pattern: /(?:^|['"=\s:])(?<key>ghu_[A-Za-z0-9_]{36,})(?:['";\s,\n]|$)/gm,
    severity: Severity.High,
    description:
      "GitHub User-to-Server Token (ghu_) detected. This token is used for GitHub App user-to-server authentication.",
    confidenceModifier: 15,
  },
  {
    id: "github-server-to-server",
    name: "GitHub Server-to-Server Token",
    pattern: /(?:^|['"=\s:])(?<key>ghs_[A-Za-z0-9_]{36,})(?:['";\s,\n]|$)/gm,
    severity: Severity.Critical,
    description:
      "GitHub Server-to-Server Token (ghs_) detected. This installation access token grants the GitHub App's permissions.",
    confidenceModifier: 20,
  },
  {
    id: "github-refresh",
    name: "GitHub Refresh Token",
    pattern: /(?:^|['"=\s:])(?<key>ghr_[A-Za-z0-9_]{36,})(?:['";\s,\n]|$)/gm,
    severity: Severity.High,
    description:
      "GitHub Refresh Token (ghr_) detected. This token can be used to generate new access tokens.",
    confidenceModifier: 15,
  },
  // --- Slack ---
  {
    id: "slack-bot-token",
    name: "Slack Bot Token",
    pattern: /(?:^|['"=\s:])(?<key>xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,})(?:['";\s,\n]|$)/gm,
    severity: Severity.High,
    description:
      "Slack Bot Token (xoxb-) detected. This token grants bot-level access to a Slack workspace, enabling message reading/sending.",
    confidenceModifier: 15,
  },
  {
    id: "slack-user-token",
    name: "Slack User Token",
    pattern: /(?:^|['"=\s:])(?<key>xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32})(?:['";\s,\n]|$)/gm,
    severity: Severity.Critical,
    description:
      "Slack User Token (xoxp-) detected. This token grants user-level access to a Slack workspace with the user's full permissions.",
    confidenceModifier: 20,
  },
  // --- Google ---
  {
    id: "google-api-key",
    name: "Google API Key",
    pattern: /(?:^|['"=\s:])(?<key>AIza[0-9A-Za-z\-_]{35})(?:['";\s,\n]|$)/gm,
    severity: Severity.High,
    description:
      "Google API Key detected. Depending on API restrictions, this key could grant access to Google Cloud services, Maps, Firebase, etc.",
    confidenceModifier: 15,
  },
  {
    id: "google-oauth-id",
    name: "Google OAuth Client ID",
    pattern: /(?<key>[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com)/g,
    severity: Severity.Medium,
    description:
      "Google OAuth Client ID detected. While not a secret by itself, it can be combined with a client secret for OAuth authentication abuse.",
    confidenceModifier: 5,
  },
  // --- JWT ---
  {
    id: "jwt-token",
    name: "JWT Token",
    pattern: /(?:^|['"=\s:])(?<key>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?:['";\s,\n]|$)/gm,
    severity: Severity.High,
    description:
      "Hardcoded JWT token detected. JWT tokens may contain sensitive claims (user ID, roles, permissions) and can be used for authentication if still valid.",
    confidenceModifier: 10,
  },
  // --- Private Keys ---
  {
    id: "rsa-private-key",
    name: "RSA Private Key",
    pattern: /-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----/g,
    severity: Severity.Critical,
    description:
      "RSA Private Key detected in source code. Private keys must never be stored in version control as they can be used for authentication, decryption, and signing.",
    confidenceModifier: 25,
  },
  {
    id: "ec-private-key",
    name: "EC Private Key",
    pattern: /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----/g,
    severity: Severity.Critical,
    description:
      "Elliptic Curve Private Key detected in source code. Private keys must be stored in secure key management systems, not in code repositories.",
    confidenceModifier: 25,
  },
  {
    id: "openssh-private-key",
    name: "OpenSSH Private Key",
    pattern: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/g,
    severity: Severity.Critical,
    description:
      "OpenSSH Private Key detected. This key can be used for SSH authentication to servers, potentially granting full shell access.",
    confidenceModifier: 25,
  },
  {
    id: "pgp-private-key",
    name: "PGP Private Key Block",
    pattern: /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/g,
    severity: Severity.Critical,
    description:
      "PGP Private Key Block detected. This key can be used for decryption, signing, and impersonation.",
    confidenceModifier: 25,
  },
  // --- Database Connection Strings ---
  {
    id: "db-connection-string",
    name: "Database Connection String",
    pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql|redis|amqp):\/\/[^\s'"]{10,}/gi,
    severity: Severity.Critical,
    description:
      "Database connection string with embedded credentials detected. This provides direct access to the database, potentially exposing all stored data.",
    confidenceModifier: 20,
  },
  // --- Stripe ---
  {
    id: "stripe-secret-key",
    name: "Stripe Secret Key",
    pattern: /(?:^|['"=\s:])(?<key>sk_live_[0-9a-zA-Z]{24,})(?:['";\s,\n]|$)/gm,
    severity: Severity.Critical,
    description:
      "Stripe Live Secret Key detected. This key grants full access to a Stripe account, enabling charges, refunds, and customer data access.",
    confidenceModifier: 25,
  },
  {
    id: "stripe-restricted-key",
    name: "Stripe Restricted Key",
    pattern: /(?:^|['"=\s:])(?<key>rk_live_[0-9a-zA-Z]{24,})(?:['";\s,\n]|$)/gm,
    severity: Severity.High,
    description:
      "Stripe Live Restricted Key detected. This key grants limited access to specific Stripe API resources.",
    confidenceModifier: 15,
  },
  {
    id: "stripe-publishable-key-live",
    name: "Stripe Publishable Key (Live)",
    pattern: /(?:^|['"=\s:])(?<key>pk_live_[0-9a-zA-Z]{24,})(?:['";\s,\n]|$)/gm,
    severity: Severity.Low,
    description:
      "Stripe Live Publishable Key detected. While designed to be public, its presence in server code may indicate a configuration issue.",
    confidenceModifier: -10,
  },
  // --- Twilio ---
  {
    id: "twilio-api-key",
    name: "Twilio API Key",
    pattern: /(?:^|['"=\s:])(?<key>SK[0-9a-fA-F]{32})(?:['";\s,\n]|$)/gm,
    severity: Severity.High,
    description:
      "Twilio API Key detected. This key grants access to Twilio services including SMS, voice, and video.",
    confidenceModifier: 10,
  },
  {
    id: "twilio-account-sid",
    name: "Twilio Account SID",
    pattern: /(?:^|['"=\s:])(?<key>AC[0-9a-fA-F]{32})(?:['";\s,\n]|$)/gm,
    severity: Severity.Medium,
    description:
      "Twilio Account SID detected. While not a secret by itself, it is often found alongside auth tokens.",
    confidenceModifier: 0,
  },
  // --- SendGrid ---
  {
    id: "sendgrid-api-key",
    name: "SendGrid API Key",
    pattern: /(?:^|['"=\s:])(?<key>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?:['";\s,\n]|$)/gm,
    severity: Severity.High,
    description:
      "SendGrid API Key detected. This key grants access to send emails on behalf of the account, which can be used for phishing.",
    confidenceModifier: 20,
  },
  // --- Firebase ---
  {
    id: "firebase-config",
    name: "Firebase Configuration",
    pattern: /(?:firebaseConfig|firebase_config)\s*=\s*\{[^}]*apiKey\s*:\s*['"][^'"]+['"]/g,
    severity: Severity.Medium,
    description:
      "Firebase configuration with API key detected. While Firebase API keys are semi-public, server-side exposure may indicate overly permissive security rules.",
    confidenceModifier: 0,
  },
  {
    id: "firebase-service-account",
    name: "Firebase Service Account Key",
    pattern: /"type"\s*:\s*"service_account"[\s\S]*?"private_key"\s*:\s*"/g,
    severity: Severity.Critical,
    description:
      "Firebase Service Account private key detected. This grants admin-level access to all Firebase services in the project.",
    confidenceModifier: 25,
  },
  // --- Azure ---
  {
    id: "azure-storage-key",
    name: "Azure Storage Account Key",
    pattern: /(?:AccountKey|DefaultEndpointsProtocol)=[^;'"]{20,}/g,
    severity: Severity.Critical,
    description:
      "Azure Storage Account Key detected. This key grants full read/write/delete access to the storage account and all its containers.",
    confidenceModifier: 20,
  },
  {
    id: "azure-ad-client-secret",
    name: "Azure AD Client Secret",
    pattern: /(?:client_secret|clientSecret|AZURE_CLIENT_SECRET)\s*[=:]\s*['"]?[A-Za-z0-9~._-]{34,}['"]?/gi,
    severity: Severity.High,
    description:
      "Azure Active Directory client secret detected. This can be used to authenticate as a service principal.",
    confidenceModifier: 10,
  },
  // --- Generic API Keys ---
  {
    id: "generic-api-key",
    name: "Generic API Key",
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi,
    severity: Severity.High,
    description:
      "Generic API key assignment detected. Hardcoded API keys in source code can be extracted by anyone with repository access.",
    confidenceModifier: 5,
  },
  {
    id: "generic-secret",
    name: "Generic Secret Assignment",
    pattern: /(?:secret|SECRET|password|PASSWORD|passwd|PASSWD)\s*[=:]\s*['"][^'"]{8,}['"]/g,
    severity: Severity.High,
    description:
      "Hardcoded secret or password assignment detected. Secrets must be stored in environment variables or a secrets manager.",
    confidenceModifier: 5,
  },
  // --- Mailgun ---
  {
    id: "mailgun-api-key",
    name: "Mailgun API Key",
    pattern: /(?:^|['"=\s:])(?<key>key-[0-9a-zA-Z]{32})(?:['";\s,\n]|$)/gm,
    severity: Severity.High,
    description:
      "Mailgun API Key detected. This key grants access to send emails through the Mailgun service.",
    confidenceModifier: 15,
  },
  // --- Heroku ---
  {
    id: "heroku-api-key",
    name: "Heroku API Key",
    pattern: /(?:HEROKU_API_KEY|heroku_api_key)\s*[=:]\s*['"]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['"]?/gi,
    severity: Severity.High,
    description:
      "Heroku API Key detected. This key grants full access to the Heroku account including app deployment and management.",
    confidenceModifier: 15,
  },
  // --- NPM ---
  {
    id: "npm-token",
    name: "NPM Access Token",
    pattern: /(?:^|['"=\s:])(?<key>npm_[A-Za-z0-9]{36,})(?:['";\s,\n]|$)/gm,
    severity: Severity.High,
    description:
      "NPM Access Token detected. This token grants publish access to npm packages, enabling supply chain attacks.",
    confidenceModifier: 20,
  },
];

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2 MB

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".svn", ".hg", "dist", "build", "out",
  ".next", "__pycache__", ".venv", "venv", "vendor", "target",
  ".idea", ".vscode", "coverage", ".nyc_output",
]);

const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".webm",
  ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
  ".exe", ".dll", ".so", ".dylib", ".bin",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx",
  ".wasm", ".map", ".pyc", ".class",
]);

// Shannon entropy thresholds
const ENTROPY_THRESHOLD_HEX = 3.5;
const ENTROPY_THRESHOLD_BASE64 = 4.5;
const MIN_HIGH_ENTROPY_LENGTH = 16;

// ---------------------------------------------------------------------------
// SecretScanner
// ---------------------------------------------------------------------------

export class SecretScanner implements ScanModule {
  readonly name = "code:secrets";

  private gitignorePatterns: string[] = [];

  async init(target: string, _options: Record<string, unknown>): Promise<void> {
    this.gitignorePatterns = await this.loadGitignore(target);
    log.info(
      { target, gitignoreRules: this.gitignorePatterns.length },
      "SecretScanner initialized",
    );
  }

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    log.info({ target }, "Starting secret detection scan");

    const maxDepth = (options.maxDepth as number) ?? 20;
    const enableEntropy = (options.enableEntropy as boolean) ?? true;

    let filesScanned = 0;
    let secretsFound = 0;

    for await (const filePath of this.walkDirectory(target, maxDepth, 0)) {
      const ext = extname(filePath).toLowerCase();

      // Skip binary files
      if (BINARY_EXTENSIONS.has(ext)) continue;

      // Respect .gitignore patterns
      const relPath = relative(target, filePath);
      if (this.isGitignored(relPath)) continue;

      // Read file content
      let content: string;
      try {
        const fileStat = await stat(filePath);
        if (fileStat.size > MAX_FILE_SIZE) continue;
        content = await readFile(filePath, "utf-8");
      } catch {
        continue;
      }

      // Detect NUL bytes (binary file masquerading with text extension)
      if (content.includes("\0")) continue;

      filesScanned++;
      const lines = content.split("\n");

      // --- Regex Pattern Matching ---
      for (const secretPattern of SECRET_PATTERNS) {
        const regex = new RegExp(
          secretPattern.pattern.source,
          secretPattern.pattern.flags,
        );
        let match: RegExpExecArray | null;

        while ((match = regex.exec(content)) !== null) {
          const lineNumber = this.offsetToLine(content, match.index);
          const lineContent = lines[lineNumber - 1] ?? "";

          // Skip if the match is in a comment explaining the format
          if (this.isLikelyFalsePositive(lineContent, match[0])) continue;

          secretsFound++;

          // Mask the secret for safe display
          const matchedText = match.groups?.key ?? match[0];
          const maskedSecret = this.maskSecret(matchedText);

          yield this.buildFinding(
            secretPattern.name,
            secretPattern.description,
            secretPattern.severity,
            target,
            filePath,
            lineNumber,
            maskedSecret,
            matchedText.length,
            secretPattern.id,
            70 + secretPattern.confidenceModifier,
          );

          if (match[0].length === 0) {
            regex.lastIndex++;
          }
        }
      }

      // --- Shannon Entropy Detection ---
      if (enableEntropy) {
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // Skip comment lines and very short lines
          if (!line || line.trim().startsWith("//") || line.trim().startsWith("#") || line.trim().startsWith("*")) {
            continue;
          }

          const highEntropyStrings = this.findHighEntropyStrings(line);
          for (const hes of highEntropyStrings) {
            // Avoid duplicate findings from regex patterns
            if (this.isAlreadyCoveredByPattern(hes.value, content)) continue;

            secretsFound++;

            yield this.buildFinding(
              "High-Entropy String (Potential Secret)",
              `A high-entropy string (Shannon entropy: ${hes.entropy.toFixed(2)}) was detected that may be a hardcoded secret, API key, or token.`,
              Severity.Medium,
              target,
              filePath,
              i + 1,
              this.maskSecret(hes.value),
              hes.value.length,
              "entropy-detection",
              45 + Math.round(hes.entropy * 3),
            );
          }
        }
      }
    }

    log.info(
      { target, filesScanned, secretsFound },
      "Secret detection scan complete",
    );
  }

  // -------------------------------------------------------------------------
  // Private: Finding Builder
  // -------------------------------------------------------------------------

  private buildFinding(
    title: string,
    description: string,
    severity: Severity,
    target: string,
    filePath: string,
    lineNumber: number,
    maskedSecret: string,
    secretLength: number,
    patternId: string,
    confidence: number,
  ): Finding {
    const vulnerability: Vulnerability = {
      id: generateUUID(),
      title: `${title} in ${relative(target, filePath)}:${lineNumber}`,
      description,
      severity,
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore: severity === Severity.Critical ? 9.1 : severity === Severity.High ? 7.5 : severity === Severity.Medium ? 5.3 : 3.1,
      cweId: "CWE-798",
      target,
      endpoint: filePath,
      evidence: {
        description: `Secret detected at line ${lineNumber}`,
        matchedPattern: maskedSecret,
        extra: {
          filePath,
          lineNumber,
          secretLength,
          patternId,
        },
      },
      remediation:
        "Remove the secret from source code immediately. Rotate the compromised credential. Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler). Add the file to .gitignore if it contains configuration. Run 'git filter-branch' or 'git-filter-repo' to remove the secret from git history.",
      references: [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
      ],
      confirmed: false,
      falsePositive: false,
      discoveredAt: new Date().toISOString(),
    };

    return {
      vulnerability,
      module: this.name,
      confidence: Math.max(5, Math.min(95, confidence)),
      timestamp: new Date().toISOString(),
      rawData: {
        patternId,
        filePath,
        lineNumber,
        maskedSecret,
      },
    };
  }

  // -------------------------------------------------------------------------
  // Private: Shannon Entropy
  // -------------------------------------------------------------------------

  /**
   * Calculate Shannon entropy of a string. Higher values indicate more
   * randomness, which is characteristic of secrets and keys.
   */
  private shannonEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;

    const freq = new Map<string, number>();
    for (const char of str) {
      freq.set(char, (freq.get(char) ?? 0) + 1);
    }

    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / len;
      if (p > 0) {
        entropy -= p * Math.log2(p);
      }
    }

    return entropy;
  }

  /**
   * Extract high-entropy substrings from a line of code.
   * Looks for quoted strings and unquoted tokens that exceed entropy thresholds.
   */
  private findHighEntropyStrings(line: string): Array<{ value: string; entropy: number }> {
    const results: Array<{ value: string; entropy: number }> = [];

    // Extract strings between quotes
    const stringRegex = /['"]([^'"]{16,})['"]/g;
    let match: RegExpExecArray | null;

    while ((match = stringRegex.exec(line)) !== null) {
      const candidate = match[1];
      if (candidate.length < MIN_HIGH_ENTROPY_LENGTH) continue;

      // Skip URLs, file paths, and common non-secret patterns
      if (this.isLikelyNonSecret(candidate)) continue;

      const entropy = this.shannonEntropy(candidate);
      const isHex = /^[0-9a-fA-F]+$/.test(candidate);
      const threshold = isHex ? ENTROPY_THRESHOLD_HEX : ENTROPY_THRESHOLD_BASE64;

      if (entropy > threshold) {
        results.push({ value: candidate, entropy });
      }
    }

    // Also check for unquoted assignment values like key=VALUE
    const assignmentRegex = /(?:key|secret|token|password|api_key)\s*[=:]\s*([A-Za-z0-9+/=_-]{16,})/gi;
    while ((match = assignmentRegex.exec(line)) !== null) {
      const candidate = match[1];
      if (candidate.length < MIN_HIGH_ENTROPY_LENGTH) continue;
      if (this.isLikelyNonSecret(candidate)) continue;

      const entropy = this.shannonEntropy(candidate);
      if (entropy > ENTROPY_THRESHOLD_BASE64) {
        results.push({ value: candidate, entropy });
      }
    }

    return results;
  }

  /**
   * Check if a string is likely a non-secret value (URL, path, placeholder, etc.)
   */
  private isLikelyNonSecret(value: string): boolean {
    // Common non-secret patterns
    if (value.startsWith("http://") || value.startsWith("https://")) return true;
    if (value.startsWith("/") && value.includes("/")) return true;
    if (value.includes("example") || value.includes("placeholder")) return true;
    if (value.includes("test") || value.includes("dummy")) return true;
    if (value.includes("TODO") || value.includes("FIXME")) return true;
    // Package names / imports
    if (value.includes(".") && value.includes("/") && !value.includes("@")) return true;
    // Repeated characters
    if (/^(.)\1+$/.test(value)) return true;
    // All zeros or sequential
    if (/^0+$/.test(value) || value === "1234567890123456") return true;
    return false;
  }

  /**
   * Check if a high-entropy string was already detected by a regex pattern.
   */
  private isAlreadyCoveredByPattern(value: string, fullContent: string): boolean {
    for (const sp of SECRET_PATTERNS) {
      const regex = new RegExp(sp.pattern.source, sp.pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(fullContent)) !== null) {
        if (match[0].includes(value)) return true;
        if (match[0].length === 0) break;
      }
    }
    return false;
  }

  // -------------------------------------------------------------------------
  // Private: False Positive Filtering
  // -------------------------------------------------------------------------

  /**
   * Check if a match is likely a false positive (in a comment explaining
   * format, or a test/example value).
   */
  private isLikelyFalsePositive(lineContent: string, matchedText: string): boolean {
    const trimmed = lineContent.trim().toLowerCase();

    // Comment lines explaining secret formats
    if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) {
      // Allow if the secret looks real (high entropy)
      if (this.shannonEntropy(matchedText) < 3.0) return true;
    }

    // Example/placeholder values
    if (
      trimmed.includes("example") ||
      trimmed.includes("placeholder") ||
      trimmed.includes("your-") ||
      trimmed.includes("your_") ||
      trimmed.includes("xxx") ||
      trimmed.includes("replace-me")
    ) {
      return true;
    }

    return false;
  }

  // -------------------------------------------------------------------------
  // Private: Secret Masking
  // -------------------------------------------------------------------------

  /**
   * Mask a secret value for safe display in findings, preserving the first
   * and last 4 characters.
   */
  private maskSecret(secret: string): string {
    if (secret.length <= 8) {
      return "*".repeat(secret.length);
    }
    const visible = Math.min(4, Math.floor(secret.length / 4));
    return (
      secret.slice(0, visible) +
      "*".repeat(secret.length - visible * 2) +
      secret.slice(-visible)
    );
  }

  // -------------------------------------------------------------------------
  // Private: .gitignore Support
  // -------------------------------------------------------------------------

  /**
   * Load .gitignore patterns from the target directory and all parent
   * directories up to the git root.
   */
  private async loadGitignore(targetDir: string): Promise<string[]> {
    const patterns: string[] = [];
    let dir = targetDir;

    // Walk up to find .gitignore files (up to 10 levels or until root)
    for (let i = 0; i < 10; i++) {
      const gitignorePath = join(dir, ".gitignore");
      try {
        await access(gitignorePath);
        const content = await readFile(gitignorePath, "utf-8");
        const filePatterns = content
          .split("\n")
          .map((line) => line.trim())
          .filter((line) => line && !line.startsWith("#"));
        patterns.push(...filePatterns);
      } catch {
        // .gitignore not found at this level, continue
      }

      const parent = dirname(dir);
      if (parent === dir) break; // reached filesystem root
      dir = parent;

      // Stop if we found a .git directory
      try {
        await access(join(dir, ".git"));
      } catch {
        continue;
      }
    }

    return patterns;
  }

  /**
   * Check if a relative file path matches any .gitignore pattern.
   * Uses a simplified glob matching approach.
   */
  private isGitignored(relPath: string): boolean {
    for (const pattern of this.gitignorePatterns) {
      // Simple pattern matching (not a full .gitignore parser, but covers most cases)
      if (pattern.endsWith("/")) {
        // Directory pattern
        const dirName = pattern.slice(0, -1);
        if (relPath.startsWith(dirName + "/") || relPath.includes("/" + dirName + "/")) {
          return true;
        }
      } else if (pattern.includes("*")) {
        // Wildcard pattern - convert to simple regex
        const regexStr = pattern
          .replace(/[.+^${}()|[\]\\]/g, "\\$&")
          .replace(/\*\*/g, ".*")
          .replace(/\*/g, "[^/]*");
        try {
          if (new RegExp(regexStr).test(relPath)) return true;
        } catch {
          // Invalid regex from pattern conversion, skip
        }
      } else {
        // Exact match or suffix match
        if (relPath === pattern || relPath.endsWith("/" + pattern) || relPath.startsWith(pattern + "/")) {
          return true;
        }
      }
    }
    return false;
  }

  // -------------------------------------------------------------------------
  // Private: Directory Walker
  // -------------------------------------------------------------------------

  private async *walkDirectory(
    dir: string,
    maxDepth: number,
    currentDepth: number,
  ): AsyncGenerator<string> {
    if (currentDepth > maxDepth) return;

    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (entry.name.startsWith(".")) continue;
        yield* this.walkDirectory(fullPath, maxDepth, currentDepth + 1);
      } else if (entry.isFile()) {
        yield fullPath;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Private: Utility
  // -------------------------------------------------------------------------

  private offsetToLine(content: string, offset: number): number {
    let line = 1;
    for (let i = 0; i < offset && i < content.length; i++) {
      if (content[i] === "\n") line++;
    }
    return line;
  }
}
