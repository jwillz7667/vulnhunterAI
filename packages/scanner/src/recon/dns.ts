// =============================================================================
// @vulnhunter/scanner - DNS Enumeration Module
// =============================================================================
// Comprehensive DNS reconnaissance:
//   1. Record type enumeration (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV)
//   2. DNS zone transfer attempt (AXFR)
//   3. SPF/DKIM/DMARC record analysis
//   4. Reverse DNS lookup
//   5. DNS cache snooping
// =============================================================================

import { randomBytes } from "crypto";
import {
  Resolver,
  resolve4,
  resolve6,
  resolveCname,
  resolveMx,
  resolveNs,
  resolveTxt,
  resolveSoa,
  resolveSrv,
  reverse,
} from "dns/promises";
import * as net from "net";
import type { ScanModule } from "../engine.js";
import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { createLogger } from "@vulnhunter/core";

const log = createLogger("recon:dns");

// ---------------------------------------------------------------------------
// UUID helper
// ---------------------------------------------------------------------------
function uuid(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DnsRecordResult {
  type: string;
  records: unknown[];
  raw?: string;
}

interface EmailSecurityAnalysis {
  spf: {
    exists: boolean;
    record?: string;
    issues: string[];
  };
  dkim: {
    exists: boolean;
    selectors: string[];
  };
  dmarc: {
    exists: boolean;
    record?: string;
    policy?: string;
    issues: string[];
  };
}

// ---------------------------------------------------------------------------
// DnsEnumerator
// ---------------------------------------------------------------------------

export class DnsEnumerator implements ScanModule {
  readonly name = "recon:dns";

  private resolver!: Resolver;
  private timeoutMs = 10000;

  async init(
    _target: string,
    options: Record<string, unknown>,
  ): Promise<void> {
    this.resolver = new Resolver();
    this.resolver.setServers(["8.8.8.8", "1.1.1.1", "8.8.4.4"]);

    if (typeof options.requestTimeoutMs === "number") {
      this.timeoutMs = options.requestTimeoutMs;
    }

    log.info("DnsEnumerator initialized");
  }

  async *execute(
    target: string,
    _options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const domain = this.extractDomain(target);
    log.info({ domain }, "Starting DNS enumeration");

    // --- Phase 1: Standard record enumeration ---
    const records = await this.enumerateRecords(domain);
    if (records.length > 0) {
      yield this.createRecordsFinding(domain, records);
    }

    // --- Phase 2: Zone transfer attempt ---
    const axfrResult = await this.attemptZoneTransfer(domain);
    if (axfrResult.success) {
      yield this.createZoneTransferFinding(domain, axfrResult);
    }

    // --- Phase 3: Email security analysis (SPF/DKIM/DMARC) ---
    const emailSecurity = await this.analyzeEmailSecurity(domain);
    const emailFindings = this.assessEmailSecurity(domain, emailSecurity);
    for (const finding of emailFindings) {
      yield finding;
    }

    // --- Phase 4: Reverse DNS lookups ---
    const aRecords = records.find((r) => r.type === "A");
    if (aRecords && Array.isArray(aRecords.records)) {
      const reverseDns = await this.reverseResolve(
        aRecords.records as string[],
      );
      if (reverseDns.length > 0) {
        yield this.createReverseDnsFinding(domain, reverseDns);
      }
    }

    // --- Phase 5: DNS cache snooping ---
    const cacheSnoop = await this.dnsCacheSnoop(domain);
    if (cacheSnoop.length > 0) {
      yield this.createCacheSnoopFinding(domain, cacheSnoop);
    }

    log.info({ domain }, "DNS enumeration complete");
  }

  async cleanup(): Promise<void> {
    log.info("DnsEnumerator cleanup complete");
  }

  // -------------------------------------------------------------------------
  // Record Enumeration
  // -------------------------------------------------------------------------

  private async enumerateRecords(
    domain: string,
  ): Promise<DnsRecordResult[]> {
    const results: DnsRecordResult[] = [];

    // A records
    const aRecords = await this.safeResolve(
      () => resolve4(domain),
      "A",
    );
    if (aRecords) results.push(aRecords);

    // AAAA records
    const aaaaRecords = await this.safeResolve(
      () => resolve6(domain),
      "AAAA",
    );
    if (aaaaRecords) results.push(aaaaRecords);

    // CNAME records
    const cnameRecords = await this.safeResolve(
      () => resolveCname(domain),
      "CNAME",
    );
    if (cnameRecords) results.push(cnameRecords);

    // MX records
    const mxRecords = await this.safeResolve(
      () => resolveMx(domain),
      "MX",
    );
    if (mxRecords) results.push(mxRecords);

    // NS records
    const nsRecords = await this.safeResolve(
      () => resolveNs(domain),
      "NS",
    );
    if (nsRecords) results.push(nsRecords);

    // TXT records
    const txtRecords = await this.safeResolve(
      () => resolveTxt(domain),
      "TXT",
    );
    if (txtRecords) results.push(txtRecords);

    // SOA records
    const soaRecords = await this.safeResolve(
      () => resolveSoa(domain),
      "SOA",
    );
    if (soaRecords) results.push(soaRecords);

    // SRV records for common services
    const srvPrefixes = [
      "_sip._tcp",
      "_sip._udp",
      "_xmpp-client._tcp",
      "_xmpp-server._tcp",
      "_autodiscover._tcp",
      "_ldap._tcp",
      "_kerberos._tcp",
      "_http._tcp",
      "_https._tcp",
      "_imap._tcp",
      "_imaps._tcp",
      "_submission._tcp",
      "_caldav._tcp",
      "_carddav._tcp",
    ];

    for (const prefix of srvPrefixes) {
      const srvDomain = `${prefix}.${domain}`;
      const srvRecords = await this.safeResolve(
        () => resolveSrv(srvDomain),
        `SRV (${prefix})`,
      );
      if (srvRecords && srvRecords.records.length > 0) {
        results.push({
          type: `SRV:${prefix}`,
          records: srvRecords.records,
        });
      }
    }

    log.info(
      { domain, recordTypes: results.map((r) => r.type) },
      "DNS record enumeration complete",
    );

    return results;
  }

  private async safeResolve<T>(
    fn: () => Promise<T>,
    type: string,
  ): Promise<DnsRecordResult | null> {
    try {
      const result = await Promise.race([
        fn(),
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error("DNS query timeout")),
            this.timeoutMs,
          ),
        ),
      ]);

      // Normalize result to an array
      const records = Array.isArray(result) ? result : [result];
      if (records.length === 0) return null;

      return { type, records };
    } catch (error) {
      const msg =
        error instanceof Error ? error.message : String(error);
      // ENODATA and ENOTFOUND are expected for missing record types
      if (!msg.includes("ENODATA") && !msg.includes("ENOTFOUND") && !msg.includes("timeout")) {
        log.debug(
          { type, error: msg },
          "DNS resolve error",
        );
      }
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Zone Transfer (AXFR)
  // -------------------------------------------------------------------------

  private async attemptZoneTransfer(
    domain: string,
  ): Promise<{
    success: boolean;
    nameserver?: string;
    records: string[];
  }> {
    // First, get NS records
    let nameservers: string[] = [];
    try {
      nameservers = await resolveNs(domain);
    } catch {
      log.debug({ domain }, "Could not resolve NS records for AXFR");
      return { success: false, records: [] };
    }

    // Attempt AXFR against each nameserver
    for (const ns of nameservers) {
      try {
        const records = await this.axfrQuery(domain, ns);
        if (records.length > 0) {
          log.warn(
            { domain, ns, recordCount: records.length },
            "DNS zone transfer succeeded - critical finding",
          );
          return { success: true, nameserver: ns, records };
        }
      } catch (error) {
        log.debug(
          {
            domain,
            ns,
            error:
              error instanceof Error ? error.message : String(error),
          },
          "AXFR attempt failed (expected)",
        );
      }
    }

    return { success: false, records: [] };
  }

  /**
   * Perform an AXFR (zone transfer) query using raw TCP.
   * AXFR uses TCP and a specific DNS wire format.
   */
  private async axfrQuery(
    domain: string,
    nameserver: string,
  ): Promise<string[]> {
    return new Promise((resolve, reject) => {
      const records: string[] = [];
      const socket = new net.Socket();
      let dataBuffer = Buffer.alloc(0);
      let resolved = false;

      const finish = (result: string[] | Error) => {
        if (resolved) return;
        resolved = true;
        socket.removeAllListeners();
        socket.destroy();
        if (result instanceof Error) {
          reject(result);
        } else {
          resolve(result);
        }
      };

      socket.setTimeout(this.timeoutMs);

      socket.on("timeout", () => {
        finish(new Error("AXFR timeout"));
      });

      socket.on("error", (err) => {
        finish(err);
      });

      socket.on("connect", () => {
        // Build a minimal AXFR DNS query
        const query = this.buildAxfrQuery(domain);
        // TCP DNS messages are prefixed with a 2-byte length
        const lengthPrefix = Buffer.alloc(2);
        lengthPrefix.writeUInt16BE(query.length, 0);
        socket.write(Buffer.concat([lengthPrefix, query]));
      });

      socket.on("data", (data: Buffer) => {
        dataBuffer = Buffer.concat([dataBuffer, data]);

        // Try to parse DNS response records from the buffer
        // AXFR responses contain the zone data; if we get any response,
        // it means the transfer was at least partially successful
        try {
          if (dataBuffer.length > 4) {
            // Read the TCP length prefix
            const msgLen = dataBuffer.readUInt16BE(0);
            if (dataBuffer.length >= msgLen + 2) {
              const dnsMessage = dataBuffer.subarray(2, msgLen + 2);

              // Check the RCODE (last 4 bits of byte 3)
              if (dnsMessage.length >= 4) {
                const rcode = dnsMessage[3] & 0x0f;
                if (rcode !== 0) {
                  // Non-zero rcode means transfer refused/failed
                  finish([]);
                  return;
                }

                // Check ANCOUNT (answer count) at bytes 6-7
                const ancount = dnsMessage.readUInt16BE(6);
                if (ancount > 0) {
                  // Zone transfer returned records
                  records.push(
                    `AXFR returned ${ancount} answer record(s) from ${nameserver}`,
                  );

                  // Try to extract readable domain names from the response
                  const responseText = dnsMessage.toString("utf8");
                  const domainPattern = /[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*/gi;
                  let domainMatch: RegExpExecArray | null;
                  const seen = new Set<string>();
                  while ((domainMatch = domainPattern.exec(responseText)) !== null) {
                    const found = domainMatch[0];
                    if (found.includes(".") && found.length > 4 && !seen.has(found)) {
                      seen.add(found);
                      records.push(found);
                    }
                  }
                }
              }

              finish(records);
            }
          }
        } catch {
          // Parsing error - not a valid response
        }
      });

      socket.on("end", () => {
        finish(records);
      });

      // Resolve nameserver hostname to IP first
      resolve4(nameserver)
        .then((ips) => {
          if (ips.length === 0) {
            finish(new Error("Could not resolve nameserver IP"));
            return;
          }
          socket.connect(53, ips[0]);
        })
        .catch((err) => finish(err));
    });
  }

  /**
   * Build a minimal DNS AXFR query packet.
   */
  private buildAxfrQuery(domain: string): Buffer {
    // Transaction ID (2 bytes)
    const transId = randomBytes(2);

    // Flags: standard query (0x0000) but with recursion desired
    const flags = Buffer.from([0x00, 0x00]);

    // Counts: 1 question, 0 answers, 0 authority, 0 additional
    const counts = Buffer.from([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Question section: encode domain name
    const labels = domain.split(".");
    const nameParts: Buffer[] = [];
    for (const label of labels) {
      const labelBuf = Buffer.alloc(1 + label.length);
      labelBuf[0] = label.length;
      labelBuf.write(label, 1, "ascii");
      nameParts.push(labelBuf);
    }
    nameParts.push(Buffer.from([0x00])); // Root label
    const name = Buffer.concat(nameParts);

    // QTYPE: AXFR (252 = 0x00FC)
    const qtype = Buffer.from([0x00, 0xfc]);
    // QCLASS: IN (1)
    const qclass = Buffer.from([0x00, 0x01]);

    return Buffer.concat([transId, flags, counts, name, qtype, qclass]);
  }

  // -------------------------------------------------------------------------
  // Email Security Analysis (SPF / DKIM / DMARC)
  // -------------------------------------------------------------------------

  private async analyzeEmailSecurity(
    domain: string,
  ): Promise<EmailSecurityAnalysis> {
    const analysis: EmailSecurityAnalysis = {
      spf: { exists: false, issues: [] },
      dkim: { exists: false, selectors: [] },
      dmarc: { exists: false, issues: [] },
    };

    // --- SPF ---
    try {
      const txtRecords = await resolveTxt(domain);
      for (const record of txtRecords) {
        const txt = record.join("");
        if (txt.toLowerCase().startsWith("v=spf1")) {
          analysis.spf.exists = true;
          analysis.spf.record = txt;

          // Analyze SPF record for weaknesses
          if (txt.includes("+all")) {
            analysis.spf.issues.push(
              'SPF record uses "+all" which allows any server to send email (effectively no protection)',
            );
          }
          if (txt.includes("~all")) {
            analysis.spf.issues.push(
              'SPF record uses "~all" (softfail) instead of "-all" (hardfail). Emails from unauthorized servers may still be delivered.',
            );
          }
          if (!txt.includes("all")) {
            analysis.spf.issues.push(
              "SPF record is missing an all mechanism. This may allow unauthorized email sending.",
            );
          }

          // Count DNS lookups (each include/a/mx/ptr counts)
          const lookupMechanisms = (txt.match(/(?:include|a|mx|ptr|exists):/gi) ?? []).length;
          const redirects = (txt.match(/redirect=/gi) ?? []).length;
          if (lookupMechanisms + redirects > 10) {
            analysis.spf.issues.push(
              `SPF record requires ${lookupMechanisms + redirects} DNS lookups, exceeding the 10-lookup limit (RFC 7208).`,
            );
          }
        }
      }
    } catch {
      // No TXT records
    }

    if (!analysis.spf.exists) {
      analysis.spf.issues.push("No SPF record found. The domain has no email sender authentication via SPF.");
    }

    // --- DKIM ---
    // Check common DKIM selectors
    const dkimSelectors = [
      "default",
      "google",
      "selector1",
      "selector2",
      "k1",
      "mandrill",
      "everlytickey1",
      "everlytickey2",
      "dkim",
      "mail",
      "s1",
      "s2",
      "sig1",
      "sm",
      "protonmail",
      "protonmail2",
      "protonmail3",
      "mxvault",
    ];

    for (const selector of dkimSelectors) {
      try {
        const records = await resolveTxt(`${selector}._domainkey.${domain}`);
        for (const record of records) {
          const txt = record.join("");
          if (txt.includes("v=DKIM1") || txt.includes("p=")) {
            analysis.dkim.exists = true;
            analysis.dkim.selectors.push(selector);
          }
        }
      } catch {
        // Expected for most selectors
      }
    }

    // --- DMARC ---
    try {
      const records = await resolveTxt(`_dmarc.${domain}`);
      for (const record of records) {
        const txt = record.join("");
        if (txt.toLowerCase().startsWith("v=dmarc1")) {
          analysis.dmarc.exists = true;
          analysis.dmarc.record = txt;

          // Extract policy
          const policyMatch = txt.match(/;\s*p=([^;\s]+)/i);
          if (policyMatch) {
            analysis.dmarc.policy = policyMatch[1].toLowerCase();
          }

          // Analyze policy
          if (analysis.dmarc.policy === "none") {
            analysis.dmarc.issues.push(
              'DMARC policy is set to "none" which only monitors but does not enforce email authentication. Consider "quarantine" or "reject".',
            );
          }

          // Check for rua (aggregate reports)
          if (!txt.includes("rua=")) {
            analysis.dmarc.issues.push(
              "DMARC record is missing an aggregate report URI (rua). No visibility into authentication failures.",
            );
          }

          // Check subdomain policy
          if (!txt.includes("sp=")) {
            analysis.dmarc.issues.push(
              "DMARC record is missing a subdomain policy (sp). Subdomains inherit the parent policy.",
            );
          }
        }
      }
    } catch {
      // No DMARC record
    }

    if (!analysis.dmarc.exists) {
      analysis.dmarc.issues.push(
        "No DMARC record found. The domain has no DMARC policy for email authentication enforcement.",
      );
    }

    return analysis;
  }

  private assessEmailSecurity(
    domain: string,
    analysis: EmailSecurityAnalysis,
  ): Finding[] {
    const findings: Finding[] = [];
    const now = new Date().toISOString();

    // SPF Finding
    if (analysis.spf.issues.length > 0) {
      const severity =
        !analysis.spf.exists || analysis.spf.record?.includes("+all")
          ? Severity.Medium
          : Severity.Low;

      const vulnerability: Vulnerability = {
        id: uuid(),
        title: analysis.spf.exists
          ? `SPF record has configuration issues on ${domain}`
          : `No SPF record found for ${domain}`,
        description:
          `SPF (Sender Policy Framework) analysis for ${domain}: ` +
          analysis.spf.issues.join(" ") +
          (analysis.spf.record
            ? ` Current record: "${analysis.spf.record}"`
            : ""),
        severity,
        category: VulnerabilityCategory.InformationDisclosure,
        cvssScore: severity === Severity.Medium ? 5.3 : 3.1,
        target: domain,
        endpoint: domain,
        evidence: {
          description: analysis.spf.exists
            ? "SPF record found with issues"
            : "No SPF record found",
          extra: {
            spfRecord: analysis.spf.record,
            issues: analysis.spf.issues,
          },
        },
        remediation:
          "Configure a proper SPF record with strict email sender validation. " +
          'Use "-all" to reject unauthorized senders. Example: "v=spf1 include:_spf.google.com -all"',
        references: [
          "https://tools.ietf.org/html/rfc7208",
          "https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/",
        ],
        confirmed: true,
        falsePositive: false,
        discoveredAt: now,
      };

      findings.push({
        vulnerability,
        module: this.name,
        confidence: 95,
        timestamp: now,
        rawData: { spfAnalysis: analysis.spf },
      });
    }

    // DMARC Finding
    if (analysis.dmarc.issues.length > 0) {
      const severity =
        !analysis.dmarc.exists || analysis.dmarc.policy === "none"
          ? Severity.Medium
          : Severity.Low;

      const vulnerability: Vulnerability = {
        id: uuid(),
        title: analysis.dmarc.exists
          ? `DMARC policy issues on ${domain}`
          : `No DMARC record found for ${domain}`,
        description:
          `DMARC (Domain-based Message Authentication, Reporting & Conformance) analysis for ${domain}: ` +
          analysis.dmarc.issues.join(" ") +
          (analysis.dmarc.record
            ? ` Current record: "${analysis.dmarc.record}"`
            : ""),
        severity,
        category: VulnerabilityCategory.InformationDisclosure,
        cvssScore: severity === Severity.Medium ? 5.3 : 3.1,
        target: domain,
        endpoint: `_dmarc.${domain}`,
        evidence: {
          description: analysis.dmarc.exists
            ? "DMARC record found with issues"
            : "No DMARC record found",
          extra: {
            dmarcRecord: analysis.dmarc.record,
            policy: analysis.dmarc.policy,
            issues: analysis.dmarc.issues,
          },
        },
        remediation:
          'Implement a DMARC record with at least a "quarantine" policy. ' +
          'Example: "v=DMARC1; p=reject; rua=mailto:dmarc-reports@' +
          domain +
          '"',
        references: [
          "https://tools.ietf.org/html/rfc7489",
          "https://www.cloudflare.com/learning/dns/dns-records/dns-dmarc-record/",
        ],
        confirmed: true,
        falsePositive: false,
        discoveredAt: now,
      };

      findings.push({
        vulnerability,
        module: this.name,
        confidence: 95,
        timestamp: now,
        rawData: { dmarcAnalysis: analysis.dmarc },
      });
    }

    // DKIM summary
    const dkimVuln: Vulnerability = {
      id: uuid(),
      title: analysis.dkim.exists
        ? `DKIM selectors discovered for ${domain}`
        : `No DKIM selectors found for ${domain}`,
      description: analysis.dkim.exists
        ? `DKIM (DomainKeys Identified Mail) is configured for ${domain}. ` +
          `Active selectors found: ${analysis.dkim.selectors.join(", ")}.`
        : `No DKIM selectors were found for ${domain} among commonly used selector names. ` +
          `DKIM provides email message integrity and sender authentication.`,
      severity: analysis.dkim.exists ? Severity.Info : Severity.Low,
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore: analysis.dkim.exists ? 0.0 : 3.1,
      target: domain,
      endpoint: domain,
      evidence: {
        description: analysis.dkim.exists
          ? `${analysis.dkim.selectors.length} DKIM selector(s) found`
          : "No DKIM selectors found",
        extra: {
          selectors: analysis.dkim.selectors,
          selectorsChecked: 18,
        },
      },
      remediation: analysis.dkim.exists
        ? "Ensure DKIM key rotation is performed regularly and that DKIM signing is applied to all outbound email."
        : "Configure DKIM signing for outbound email to prevent spoofing and improve deliverability.",
      references: [
        "https://tools.ietf.org/html/rfc6376",
        "https://www.cloudflare.com/learning/dns/dns-records/dns-dkim-record/",
      ],
      confirmed: true,
      falsePositive: false,
      discoveredAt: now,
    };

    findings.push({
      vulnerability: dkimVuln,
      module: this.name,
      confidence: 80,
      timestamp: now,
      rawData: { dkimAnalysis: analysis.dkim },
    });

    return findings;
  }

  // -------------------------------------------------------------------------
  // Reverse DNS
  // -------------------------------------------------------------------------

  private async reverseResolve(
    ips: string[],
  ): Promise<Array<{ ip: string; hostnames: string[] }>> {
    const results: Array<{ ip: string; hostnames: string[] }> = [];

    for (const ip of ips) {
      try {
        const hostnames = await Promise.race([
          reverse(ip),
          new Promise<string[]>((_, reject) =>
            setTimeout(
              () => reject(new Error("reverse DNS timeout")),
              this.timeoutMs,
            ),
          ),
        ]);

        if (hostnames.length > 0) {
          results.push({ ip, hostnames });
        }
      } catch {
        // No reverse DNS -- expected
      }
    }

    return results;
  }

  // -------------------------------------------------------------------------
  // DNS Cache Snooping
  // -------------------------------------------------------------------------

  /**
   * DNS cache snooping: query the target's nameservers with the
   * recursion-desired (RD) flag unset. If the server returns a cached
   * answer, it reveals that someone previously queried for that domain,
   * leaking information about internal browsing patterns.
   *
   * We probe for common high-value domains.
   */
  private async dnsCacheSnoop(
    domain: string,
  ): Promise<Array<{ domain: string; cached: boolean; nameserver: string }>> {
    const results: Array<{
      domain: string;
      cached: boolean;
      nameserver: string;
    }> = [];

    // Get the target's nameservers
    let nameservers: string[] = [];
    try {
      nameservers = await resolveNs(domain);
    } catch {
      return results;
    }

    // Domains to check for in cache
    const probeDomains = [
      "google.com",
      "facebook.com",
      "twitter.com",
      "github.com",
      "microsoft.com",
      "aws.amazon.com",
      "linkedin.com",
      "slack.com",
      "zoom.us",
      "dropbox.com",
    ];

    // Resolve NS to IP
    let nsIp: string | null = null;
    for (const ns of nameservers.slice(0, 2)) {
      try {
        const ips = await resolve4(ns);
        if (ips.length > 0) {
          nsIp = ips[0];
          break;
        }
      } catch {
        continue;
      }
    }

    if (!nsIp) return results;

    // Send non-recursive queries
    for (const probeDomain of probeDomains) {
      try {
        const cached = await this.nonRecursiveQuery(
          probeDomain,
          nsIp,
        );
        if (cached) {
          results.push({
            domain: probeDomain,
            cached: true,
            nameserver: nsIp,
          });
        }
      } catch {
        // Query failed -- not snoopable
      }
    }

    return results;
  }

  /**
   * Send a non-recursive DNS query (RD=0) and check if the nameserver
   * returns a cached response.
   */
  private async nonRecursiveQuery(
    domain: string,
    nameserverIp: string,
  ): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = net.createConnection(53, nameserverIp, () => {
        // Build DNS query with RD=0
        const query = this.buildNonRecursiveQuery(domain);
        const lengthPrefix = Buffer.alloc(2);
        lengthPrefix.writeUInt16BE(query.length, 0);
        socket.write(Buffer.concat([lengthPrefix, query]));
      });

      let resolved = false;
      const timeout = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          socket.destroy();
          resolve(false);
        }
      }, 3000);

      socket.on("data", (data: Buffer) => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timeout);
        socket.destroy();

        // Check if we got an answer (ANCOUNT > 0) and no error (RCODE = 0)
        if (data.length >= 8) {
          // Skip TCP length prefix (2 bytes)
          const offset = data.length > 14 ? 2 : 0;
          const rcode = data[offset + 3] & 0x0f;
          const ancount = data.readUInt16BE(offset + 6);
          resolve(rcode === 0 && ancount > 0);
        } else {
          resolve(false);
        }
      });

      socket.on("error", () => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          resolve(false);
        }
      });
    });
  }

  private buildNonRecursiveQuery(domain: string): Buffer {
    const transId = randomBytes(2);
    // Flags: standard query with RD=0 (byte 2 = 0x00, byte 3 = 0x00)
    const flags = Buffer.from([0x00, 0x00]);
    const counts = Buffer.from([
      0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    const labels = domain.split(".");
    const nameParts: Buffer[] = [];
    for (const label of labels) {
      const labelBuf = Buffer.alloc(1 + label.length);
      labelBuf[0] = label.length;
      labelBuf.write(label, 1, "ascii");
      nameParts.push(labelBuf);
    }
    nameParts.push(Buffer.from([0x00]));
    const name = Buffer.concat(nameParts);

    // QTYPE: A (1), QCLASS: IN (1)
    const qtype = Buffer.from([0x00, 0x01]);
    const qclass = Buffer.from([0x00, 0x01]);

    return Buffer.concat([transId, flags, counts, name, qtype, qclass]);
  }

  // -------------------------------------------------------------------------
  // Finding Factories
  // -------------------------------------------------------------------------

  private createRecordsFinding(
    domain: string,
    records: DnsRecordResult[],
  ): Finding {
    const now = new Date().toISOString();

    // Format records for the description
    const recordSummary = records
      .map((r) => {
        const count =
          Array.isArray(r.records) ? r.records.length : 1;
        return `${r.type}: ${count} record(s)`;
      })
      .join(", ");

    const vulnerability: Vulnerability = {
      id: uuid(),
      title: `DNS records enumerated for ${domain}`,
      description:
        `DNS enumeration of ${domain} revealed the following record types: ${recordSummary}. ` +
        `This information maps the domain's infrastructure including mail servers, name servers, ` +
        `and service endpoints.`,
      severity: Severity.Info,
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore: 0.0,
      target: domain,
      endpoint: domain,
      evidence: {
        description: `${records.length} DNS record type(s) enumerated`,
        extra: {
          records: records.map((r) => ({
            type: r.type,
            data: r.records,
          })),
        },
      },
      remediation:
        "Review DNS records to ensure no sensitive information is unintentionally exposed. " +
        "Remove unused records and ensure NS, MX, and TXT records are current.",
      references: [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
      ],
      confirmed: true,
      falsePositive: false,
      discoveredAt: now,
    };

    return {
      vulnerability,
      module: this.name,
      confidence: 100,
      timestamp: now,
      rawData: {
        domain,
        records: records.map((r) => ({
          type: r.type,
          data: r.records,
        })),
      },
    };
  }

  private createZoneTransferFinding(
    domain: string,
    result: {
      success: boolean;
      nameserver?: string;
      records: string[];
    },
  ): Finding {
    const now = new Date().toISOString();

    const vulnerability: Vulnerability = {
      id: uuid(),
      title: `DNS zone transfer (AXFR) successful on ${domain}`,
      description:
        `A DNS zone transfer (AXFR) was successfully performed against nameserver ${result.nameserver} ` +
        `for domain ${domain}. This exposes the complete DNS zone data including all subdomains, ` +
        `IP addresses, mail servers, and service records. Zone transfers should be restricted ` +
        `to authorized secondary nameservers only.`,
      severity: Severity.High,
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore: 7.5,
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      cweId: "CWE-200",
      target: domain,
      endpoint: result.nameserver,
      evidence: {
        description: `AXFR returned ${result.records.length} record(s) from ${result.nameserver}`,
        extra: {
          nameserver: result.nameserver,
          recordCount: result.records.length,
          sampleRecords: result.records.slice(0, 50),
        },
      },
      remediation:
        "Restrict DNS zone transfers to authorized secondary nameservers only. " +
        "Configure allow-transfer ACLs on the authoritative nameserver to deny " +
        "AXFR requests from unauthorized sources.",
      references: [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
        "https://tools.ietf.org/html/rfc5936",
      ],
      confirmed: true,
      falsePositive: false,
      discoveredAt: now,
    };

    return {
      vulnerability,
      module: this.name,
      confidence: 100,
      timestamp: now,
      rawData: {
        domain,
        nameserver: result.nameserver,
        records: result.records,
      },
    };
  }

  private createReverseDnsFinding(
    domain: string,
    reverseDns: Array<{ ip: string; hostnames: string[] }>,
  ): Finding {
    const now = new Date().toISOString();

    const vulnerability: Vulnerability = {
      id: uuid(),
      title: `Reverse DNS records found for ${domain}`,
      description:
        `Reverse DNS lookups on IP addresses associated with ${domain} revealed ` +
        `${reverseDns.length} IP(s) with PTR records. This can reveal shared hosting, ` +
        `CDN infrastructure, or internal hostnames. Entries: ` +
        reverseDns
          .map((r) => `${r.ip} -> ${r.hostnames.join(", ")}`)
          .join("; "),
      severity: Severity.Info,
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore: 0.0,
      target: domain,
      endpoint: domain,
      evidence: {
        description: `${reverseDns.length} reverse DNS record(s) found`,
        extra: { reverseDns },
      },
      remediation:
        "Review PTR records to ensure they do not expose internal hostnames or infrastructure details.",
      references: [],
      confirmed: true,
      falsePositive: false,
      discoveredAt: now,
    };

    return {
      vulnerability,
      module: this.name,
      confidence: 95,
      timestamp: now,
      rawData: { reverseDns },
    };
  }

  private createCacheSnoopFinding(
    domain: string,
    cachedDomains: Array<{
      domain: string;
      cached: boolean;
      nameserver: string;
    }>,
  ): Finding {
    const now = new Date().toISOString();
    const cachedList = cachedDomains
      .map((c) => c.domain)
      .join(", ");

    const vulnerability: Vulnerability = {
      id: uuid(),
      title: `DNS cache snooping possible on ${domain}'s nameserver`,
      description:
        `The nameserver for ${domain} responds to non-recursive queries, ` +
        `allowing DNS cache snooping. The following domains were found in the cache: ${cachedList}. ` +
        `This reveals which domains users behind this nameserver have been visiting, ` +
        `potentially leaking browsing patterns and internal service usage.`,
      severity: Severity.Low,
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore: 3.7,
      cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
      cweId: "CWE-200",
      target: domain,
      endpoint: cachedDomains[0]?.nameserver,
      evidence: {
        description: `${cachedDomains.length} domain(s) found in DNS cache`,
        extra: { cachedDomains },
      },
      remediation:
        "Configure the DNS server to ignore non-recursive queries from external sources, " +
        "or restrict recursive queries to authorized internal clients only.",
      references: [
        "https://www.sans.org/white-papers/dns-cache-snooping-is-it-a-security-concern-33839/",
      ],
      confirmed: true,
      falsePositive: false,
      discoveredAt: now,
    };

    return {
      vulnerability,
      module: this.name,
      confidence: 85,
      timestamp: now,
      rawData: { cachedDomains },
    };
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private extractDomain(target: string): string {
    let domain = target;

    if (domain.includes("://")) {
      try {
        const parsed = new URL(domain);
        domain = parsed.hostname;
      } catch {
        domain = domain.replace(/^[a-z]+:\/\//i, "");
      }
    }

    domain = domain.split(":")[0];
    domain = domain.split("/")[0];
    domain = domain.replace(/\.$/, "");

    return domain.toLowerCase();
  }
}
