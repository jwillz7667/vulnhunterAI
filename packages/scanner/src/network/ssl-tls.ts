// =============================================================================
// @vulnhunter/scanner - SSL/TLS Security Analyzer
// =============================================================================
// Analyzes SSL/TLS configurations of target hosts including certificate
// validity, protocol versions, cipher suites, HSTS headers, and certificate
// transparency. Uses Node.js TLS APIs for direct socket inspection.
// =============================================================================

import { connect as tlsConnect, type TLSSocket, type PeerCertificate } from "node:tls";
import { connect as netConnect } from "node:net";
import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { generateUUID, createLogger } from "@vulnhunter/core";
import type { ScanModule } from "../engine.js";

const log = createLogger("ssl-tls-scanner");

// ---------------------------------------------------------------------------
// Protocol / Cipher Configuration
// ---------------------------------------------------------------------------

/** TLS protocol versions to test, from weakest to strongest */
const TLS_PROTOCOLS: Array<{
  name: string;
  secureContext: string;
  minVersion?: string;
  maxVersion?: string;
  deprecated: boolean;
  severity: Severity;
}> = [
  {
    name: "TLS 1.0",
    secureContext: "TLSv1",
    maxVersion: "TLSv1",
    minVersion: "TLSv1",
    deprecated: true,
    severity: Severity.Medium,
  },
  {
    name: "TLS 1.1",
    secureContext: "TLSv1.1",
    maxVersion: "TLSv1.1",
    minVersion: "TLSv1.1",
    deprecated: true,
    severity: Severity.Medium,
  },
  {
    name: "TLS 1.2",
    secureContext: "TLSv1.2",
    maxVersion: "TLSv1.2",
    minVersion: "TLSv1.2",
    deprecated: false,
    severity: Severity.Info,
  },
  {
    name: "TLS 1.3",
    secureContext: "TLSv1.3",
    maxVersion: "TLSv1.3",
    minVersion: "TLSv1.3",
    deprecated: false,
    severity: Severity.Info,
  },
];

/** Known weak cipher suites */
const WEAK_CIPHERS = new Set([
  "DES-CBC3-SHA",
  "RC4-SHA",
  "RC4-MD5",
  "DES-CBC-SHA",
  "EXP-RC4-MD5",
  "EXP-DES-CBC-SHA",
  "EXP-RC2-CBC-MD5",
  "NULL-SHA",
  "NULL-MD5",
  "NULL-SHA256",
  "AECDH-NULL-SHA",
  "ADH-AES128-SHA",
  "ADH-AES256-SHA",
  "ADH-DES-CBC3-SHA",
  "ADH-RC4-MD5",
]);

/** Cipher patterns considered weak or problematic */
const WEAK_CIPHER_PATTERNS = [
  /RC4/i,
  /DES(?!E)/i,  // DES but not ECDHE
  /NULL/i,
  /EXPORT/i,
  /anon/i,
  /MD5/i,
  /^ADH-/i,
  /^AECDH-/i,
];

const CONNECTION_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// SslTlsScanner
// ---------------------------------------------------------------------------

export class SslTlsScanner implements ScanModule {
  readonly name = "network:ssl-tls";

  /**
   * Execute SSL/TLS analysis on the given target.
   *
   * @param target - Hostname or hostname:port to analyze
   * @param options - Scanner options
   */
  async *execute(
    target: string,
    _options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const { hostname, port } = this.parseTarget(target);

    log.info({ hostname, port }, "Starting SSL/TLS analysis");

    // 1. Certificate Analysis
    yield* this.analyzeCertificate(hostname, port, target);

    // 2. Protocol Version Detection
    yield* this.analyzeProtocols(hostname, port, target);

    // 3. Cipher Suite Analysis
    yield* this.analyzeCipherSuites(hostname, port, target);

    // 4. HSTS Header Check
    yield* this.checkHsts(hostname, target);

    log.info({ hostname, port }, "SSL/TLS analysis complete");
  }

  // -------------------------------------------------------------------------
  // Certificate Analysis
  // -------------------------------------------------------------------------

  private async *analyzeCertificate(
    hostname: string,
    port: number,
    target: string,
  ): AsyncGenerator<Finding> {
    let cert: PeerCertificate;

    try {
      cert = await this.getCertificate(hostname, port);
    } catch (err) {
      yield this.createFinding(
        "SSL/TLS Connection Failed",
        `Could not establish a TLS connection to ${hostname}:${port}. ${err instanceof Error ? err.message : String(err)}`,
        Severity.High,
        target,
        `${hostname}:${port}`,
        "CWE-295",
        7.5,
        70,
        { error: err instanceof Error ? err.message : String(err) },
      );
      return;
    }

    // Check certificate expiration
    const notAfter = new Date(cert.valid_to);
    const notBefore = new Date(cert.valid_from);
    const now = new Date();
    const daysUntilExpiry = Math.floor((notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

    if (now > notAfter) {
      yield this.createFinding(
        "Expired SSL/TLS Certificate",
        `The SSL/TLS certificate for ${hostname} expired on ${notAfter.toISOString()}. Expired certificates cause browser warnings and can indicate abandoned or misconfigured services.`,
        Severity.High,
        target,
        `${hostname}:${port}`,
        "CWE-298",
        7.5,
        95,
        { validTo: cert.valid_to, validFrom: cert.valid_from, daysExpired: Math.abs(daysUntilExpiry) },
      );
    } else if (now < notBefore) {
      yield this.createFinding(
        "Not-Yet-Valid SSL/TLS Certificate",
        `The SSL/TLS certificate for ${hostname} is not valid until ${notBefore.toISOString()}.`,
        Severity.High,
        target,
        `${hostname}:${port}`,
        "CWE-298",
        7.5,
        95,
        { validTo: cert.valid_to, validFrom: cert.valid_from },
      );
    } else if (daysUntilExpiry <= 30) {
      yield this.createFinding(
        "SSL/TLS Certificate Expiring Soon",
        `The SSL/TLS certificate for ${hostname} expires in ${daysUntilExpiry} days (${notAfter.toISOString()}). Certificates should be renewed well before expiration to avoid service disruption.`,
        Severity.Low,
        target,
        `${hostname}:${port}`,
        "CWE-298",
        3.7,
        85,
        { validTo: cert.valid_to, daysUntilExpiry },
      );
    }

    // Check subject CN / SAN match
    const rawCn = cert.subject?.CN;
    const cn: string = rawCn == null ? "" : Array.isArray(rawCn) ? rawCn[0] ?? "" : String(rawCn);
    const rawAltNames = cert.subjectaltname;
    const altNames: string = rawAltNames == null
      ? ""
      : Array.isArray(rawAltNames)
        ? rawAltNames.join(", ")
        : String(rawAltNames);
    const validNames = this.extractValidNames(cn, altNames);

    if (!this.hostnameMatchesCert(hostname, validNames)) {
      yield this.createFinding(
        "SSL/TLS Certificate Hostname Mismatch",
        `The SSL/TLS certificate for ${hostname} does not include this hostname in its subject (CN: ${cn}) or Subject Alternative Names. This causes browser security warnings and may indicate a misconfigured or spoofed certificate.`,
        Severity.High,
        target,
        `${hostname}:${port}`,
        "CWE-297",
        7.4,
        90,
        { cn, subjectAltName: altNames, validNames },
      );
    }

    // Check if self-signed
    if (cert.issuer && cert.subject) {
      const issuerStr = JSON.stringify(cert.issuer);
      const subjectStr = JSON.stringify(cert.subject);
      if (issuerStr === subjectStr) {
        yield this.createFinding(
          "Self-Signed SSL/TLS Certificate",
          `The SSL/TLS certificate for ${hostname} is self-signed (issuer matches subject). Self-signed certificates are not trusted by browsers and do not provide assurance of the server's identity.`,
          Severity.Medium,
          target,
          `${hostname}:${port}`,
          "CWE-295",
          5.3,
          90,
          { issuer: cert.issuer, subject: cert.subject },
        );
      }
    }

    // Check key length
    const bits = (cert as { bits?: number }).bits;
    if (bits && bits < 2048) {
      yield this.createFinding(
        "Weak SSL/TLS Certificate Key Length",
        `The SSL/TLS certificate for ${hostname} uses a ${bits}-bit key, which is below the recommended minimum of 2048 bits. Short keys are vulnerable to factoring attacks.`,
        Severity.Medium,
        target,
        `${hostname}:${port}`,
        "CWE-326",
        5.3,
        85,
        { keyBits: bits },
      );
    }
  }

  // -------------------------------------------------------------------------
  // Protocol Analysis
  // -------------------------------------------------------------------------

  private async *analyzeProtocols(
    hostname: string,
    port: number,
    target: string,
  ): AsyncGenerator<Finding> {
    const supportedProtocols: string[] = [];

    for (const proto of TLS_PROTOCOLS) {
      const supported = await this.testProtocol(hostname, port, proto.minVersion, proto.maxVersion);
      if (supported) {
        supportedProtocols.push(proto.name);

        if (proto.deprecated) {
          yield this.createFinding(
            `Deprecated ${proto.name} Protocol Supported`,
            `The server ${hostname}:${port} supports ${proto.name}, which is deprecated and has known security weaknesses. ${proto.name} is vulnerable to BEAST, POODLE, and other protocol-level attacks. Modern security standards (PCI DSS 3.2.1, NIST SP 800-52 Rev. 2) require TLS 1.2 as the minimum.`,
            proto.severity,
            target,
            `${hostname}:${port}`,
            "CWE-327",
            5.3,
            85,
            { protocol: proto.name, allSupported: supportedProtocols },
          );
        }
      }
    }

    // Check if TLS 1.3 is not supported (informational)
    if (!supportedProtocols.includes("TLS 1.3")) {
      yield this.createFinding(
        "TLS 1.3 Not Supported",
        `The server ${hostname}:${port} does not support TLS 1.3. While TLS 1.2 is still acceptable, TLS 1.3 provides improved security (0-RTT, fewer cipher suites, no renegotiation) and performance benefits.`,
        Severity.Info,
        target,
        `${hostname}:${port}`,
        "CWE-327",
        0.0,
        75,
        { supportedProtocols },
      );
    }
  }

  // -------------------------------------------------------------------------
  // Cipher Suite Analysis
  // -------------------------------------------------------------------------

  private async *analyzeCipherSuites(
    hostname: string,
    port: number,
    target: string,
  ): AsyncGenerator<Finding> {
    try {
      const socket = await this.connectTls(hostname, port);
      const cipher = socket.getCipher();
      socket.destroy();

      if (cipher) {
        const cipherName = cipher.name;
        const isWeak = this.isWeakCipher(cipherName);

        if (isWeak) {
          yield this.createFinding(
            `Weak Cipher Suite: ${cipherName}`,
            `The server ${hostname}:${port} negotiated a weak cipher suite (${cipherName}, ${cipher.version}). Weak ciphers can be broken through cryptanalysis, enabling decryption of intercepted traffic.`,
            Severity.Medium,
            target,
            `${hostname}:${port}`,
            "CWE-327",
            5.3,
            85,
            { cipher: cipherName, version: cipher.version, standardName: cipher.standardName },
          );
        }

        // Check for lack of forward secrecy
        if (!cipherName.includes("ECDHE") && !cipherName.includes("DHE")) {
          yield this.createFinding(
            "Cipher Suite Without Forward Secrecy",
            `The server ${hostname}:${port} negotiated cipher ${cipherName} which does not provide forward secrecy (no ECDHE or DHE key exchange). Without forward secrecy, compromise of the server's private key allows decryption of all past recorded sessions.`,
            Severity.Medium,
            target,
            `${hostname}:${port}`,
            "CWE-326",
            5.3,
            80,
            { cipher: cipherName },
          );
        }
      }
    } catch (err) {
      log.debug(
        { hostname, port, error: err instanceof Error ? err.message : String(err) },
        "Failed to analyze cipher suites",
      );
    }
  }

  // -------------------------------------------------------------------------
  // HSTS Check
  // -------------------------------------------------------------------------

  private async *checkHsts(
    hostname: string,
    target: string,
  ): AsyncGenerator<Finding> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), CONNECTION_TIMEOUT_MS);

      const response = await fetch(`https://${hostname}/`, {
        method: "HEAD",
        redirect: "follow",
        signal: controller.signal,
      });

      clearTimeout(timeout);

      const hstsHeader = response.headers.get("strict-transport-security");

      if (!hstsHeader) {
        yield this.createFinding(
          "Missing HTTP Strict Transport Security (HSTS)",
          `The server ${hostname} does not send the Strict-Transport-Security header. Without HSTS, users can be downgraded from HTTPS to HTTP via man-in-the-middle attacks, enabling session hijacking and data interception.`,
          Severity.Low,
          target,
          `https://${hostname}/`,
          "CWE-319",
          3.7,
          85,
          { header: null },
        );
      } else {
        // Parse HSTS directives
        const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
        const includeSubdomains = hstsHeader.toLowerCase().includes("includesubdomains");
        const preload = hstsHeader.toLowerCase().includes("preload");

        if (maxAge < 15768000) { // Less than 6 months
          yield this.createFinding(
            "HSTS Max-Age Too Short",
            `The HSTS header on ${hostname} has a max-age of ${maxAge} seconds (${Math.round(maxAge / 86400)} days). The recommended minimum is 6 months (15768000 seconds) for effective protection.`,
            Severity.Low,
            target,
            `https://${hostname}/`,
            "CWE-319",
            2.0,
            80,
            { hstsHeader, maxAge, includeSubdomains, preload },
          );
        }

        if (!includeSubdomains) {
          yield this.createFinding(
            "HSTS Missing includeSubDomains Directive",
            `The HSTS header on ${hostname} does not include the includeSubDomains directive. Subdomains can still be accessed via HTTP, potentially enabling cookie stealing through subdomain takeover.`,
            Severity.Info,
            target,
            `https://${hostname}/`,
            "CWE-319",
            0.0,
            75,
            { hstsHeader, includeSubdomains: false },
          );
        }
      }

      // Check for HTTP to HTTPS redirect
      try {
        const httpController = new AbortController();
        const httpTimeout = setTimeout(() => httpController.abort(), CONNECTION_TIMEOUT_MS);

        const httpResponse = await fetch(`http://${hostname}/`, {
          method: "HEAD",
          redirect: "manual",
          signal: httpController.signal,
        });

        clearTimeout(httpTimeout);

        const location = httpResponse.headers.get("location") ?? "";
        if (httpResponse.status >= 300 && httpResponse.status < 400 && location.startsWith("https://")) {
          // Good - redirecting to HTTPS
        } else if (httpResponse.status === 200) {
          yield this.createFinding(
            "HTTP Service Without HTTPS Redirect",
            `The server ${hostname} serves content over plain HTTP (port 80) without redirecting to HTTPS. This allows users to inadvertently transmit sensitive data in plaintext.`,
            Severity.Medium,
            target,
            `http://${hostname}/`,
            "CWE-319",
            5.3,
            80,
            { httpStatus: httpResponse.status },
          );
        }
      } catch {
        // HTTP port might not be open, which is fine
      }
    } catch (err) {
      log.debug(
        { hostname, error: err instanceof Error ? err.message : String(err) },
        "Failed HSTS/HTTP check",
      );
    }
  }

  // -------------------------------------------------------------------------
  // TLS Connection Helpers
  // -------------------------------------------------------------------------

  /**
   * Establish a TLS connection and retrieve the peer certificate.
   */
  private getCertificate(hostname: string, port: number): Promise<PeerCertificate> {
    return new Promise((resolve, reject) => {
      const socket = tlsConnect(
        {
          host: hostname,
          port,
          rejectUnauthorized: false, // We need to inspect invalid certs too
          servername: hostname,
        },
        () => {
          const cert = socket.getPeerCertificate(true);
          socket.destroy();
          if (cert && Object.keys(cert).length > 0) {
            resolve(cert);
          } else {
            reject(new Error("No certificate received"));
          }
        },
      );

      socket.on("error", (err) => {
        socket.destroy();
        reject(err);
      });

      socket.setTimeout(CONNECTION_TIMEOUT_MS, () => {
        socket.destroy();
        reject(new Error("Connection timed out"));
      });
    });
  }

  /**
   * Create a TLS socket connection for cipher analysis.
   */
  private connectTls(hostname: string, port: number): Promise<TLSSocket> {
    return new Promise((resolve, reject) => {
      const socket = tlsConnect(
        {
          host: hostname,
          port,
          rejectUnauthorized: false,
          servername: hostname,
        },
        () => resolve(socket),
      );

      socket.on("error", (err) => {
        socket.destroy();
        reject(err);
      });

      socket.setTimeout(CONNECTION_TIMEOUT_MS, () => {
        socket.destroy();
        reject(new Error("Connection timed out"));
      });
    });
  }

  /**
   * Test if a specific TLS protocol version is supported.
   */
  private testProtocol(
    hostname: string,
    port: number,
    minVersion?: string,
    maxVersion?: string,
  ): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = tlsConnect(
        {
          host: hostname,
          port,
          rejectUnauthorized: false,
          servername: hostname,
          minVersion: minVersion as "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3" | undefined,
          maxVersion: maxVersion as "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3" | undefined,
        },
        () => {
          socket.destroy();
          resolve(true);
        },
      );

      socket.on("error", () => {
        socket.destroy();
        resolve(false);
      });

      socket.setTimeout(CONNECTION_TIMEOUT_MS, () => {
        socket.destroy();
        resolve(false);
      });
    });
  }

  // -------------------------------------------------------------------------
  // Utility Helpers
  // -------------------------------------------------------------------------

  /**
   * Parse a target string into hostname and port.
   * Accepts: "example.com", "example.com:443", "https://example.com"
   */
  private parseTarget(target: string): { hostname: string; port: number } {
    let cleaned = target;

    // Strip protocol prefix
    if (cleaned.startsWith("https://")) cleaned = cleaned.slice(8);
    if (cleaned.startsWith("http://")) cleaned = cleaned.slice(7);

    // Strip path
    const pathIndex = cleaned.indexOf("/");
    if (pathIndex !== -1) cleaned = cleaned.slice(0, pathIndex);

    // Extract port
    const colonIndex = cleaned.lastIndexOf(":");
    if (colonIndex !== -1 && colonIndex > cleaned.lastIndexOf("]")) {
      // Not an IPv6 bracket
      const portStr = cleaned.slice(colonIndex + 1);
      const port = parseInt(portStr, 10);
      if (!isNaN(port) && port > 0 && port <= 65535) {
        return { hostname: cleaned.slice(0, colonIndex), port };
      }
    }

    return { hostname: cleaned, port: 443 };
  }

  /**
   * Extract valid hostnames from certificate CN and SAN fields.
   */
  private extractValidNames(cn: string, altNames: string): string[] {
    const names: string[] = [];

    if (cn) names.push(cn.toLowerCase());

    if (altNames) {
      // Format: "DNS:example.com, DNS:*.example.com, IP Address:1.2.3.4"
      const parts = altNames.split(",").map((s) => s.trim());
      for (const part of parts) {
        if (part.startsWith("DNS:")) {
          names.push(part.slice(4).toLowerCase());
        }
      }
    }

    return [...new Set(names)];
  }

  /**
   * Check if a hostname matches any of the certificate's valid names,
   * including wildcard matching.
   */
  private hostnameMatchesCert(hostname: string, validNames: string[]): boolean {
    const lowerHostname = hostname.toLowerCase();

    for (const name of validNames) {
      if (name === lowerHostname) return true;

      // Wildcard matching: *.example.com matches sub.example.com but not example.com
      if (name.startsWith("*.")) {
        const domain = name.slice(2);
        if (lowerHostname.endsWith(domain) && lowerHostname.includes(".")) {
          const prefix = lowerHostname.slice(0, lowerHostname.length - domain.length);
          if (prefix.endsWith(".") && !prefix.slice(0, -1).includes(".")) {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Check if a cipher name is considered weak.
   */
  private isWeakCipher(cipherName: string): boolean {
    if (WEAK_CIPHERS.has(cipherName)) return true;
    return WEAK_CIPHER_PATTERNS.some((p) => p.test(cipherName));
  }

  /**
   * Create a standardized Finding object.
   */
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
  ): Finding {
    const vulnerability: Vulnerability = {
      id: generateUUID(),
      title,
      description,
      severity,
      category: VulnerabilityCategory.Cryptographic,
      cvssScore,
      cweId,
      target,
      endpoint,
      evidence: {
        description: title,
        extra,
      },
      remediation: this.getRemediation(cweId),
      references: [
        `https://cwe.mitre.org/data/definitions/${cweId.replace("CWE-", "")}.html`,
        "https://ssl-config.mozilla.org/",
        "https://www.ssllabs.com/ssltest/",
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

  private getRemediation(cweId: string): string {
    switch (cweId) {
      case "CWE-295":
        return "Install a valid TLS certificate from a trusted Certificate Authority (Let's Encrypt, DigiCert, etc.). Ensure the certificate chain is complete.";
      case "CWE-297":
        return "Ensure the certificate's Subject Alternative Names (SANs) include all hostnames used to access the service. Regenerate the certificate with the correct names.";
      case "CWE-298":
        return "Renew the certificate before expiration. Set up automated certificate renewal (certbot, ACME protocol). Monitor certificate expiration dates.";
      case "CWE-319":
        return "Enable HSTS with a minimum max-age of 6 months: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. Redirect all HTTP traffic to HTTPS.";
      case "CWE-326":
        return "Use RSA keys of at least 2048 bits or ECDSA keys of at least 256 bits. Enable forward secrecy by preferring ECDHE key exchange.";
      case "CWE-327":
        return "Disable deprecated TLS protocols (1.0, 1.1) and weak cipher suites. Configure TLS 1.2 as minimum with AEAD ciphers (AES-GCM, ChaCha20-Poly1305). Enable TLS 1.3. Use Mozilla's SSL Configuration Generator.";
      default:
        return "Review and harden the TLS configuration using Mozilla's SSL Configuration Generator (https://ssl-config.mozilla.org/).";
    }
  }
}
