// =============================================================================
// @vulnhunter/scanner - Service Enumeration Module
// =============================================================================
// Performs banner grabbing and version detection on open ports to identify
// running services. Matches detected versions against known vulnerability
// databases for common services.
// =============================================================================

import { connect, type Socket } from "node:net";
import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { generateUUID, createLogger } from "@vulnhunter/core";
import type { ScanModule } from "../engine.js";

const log = createLogger("service-enumerator");

// ---------------------------------------------------------------------------
// Service Definitions
// ---------------------------------------------------------------------------

interface ServiceSignature {
  /** Service name (e.g., "SSH", "MySQL") */
  name: string;
  /** Default port(s) for this service */
  defaultPorts: number[];
  /** Regex to extract version from banner */
  bannerPattern: RegExp;
  /** Initial probe to send to trigger a banner (null = wait for server to speak first) */
  probe: Buffer | null;
  /** Known vulnerable version ranges */
  knownVulnerableVersions: Array<{
    versionPattern: RegExp;
    cveId: string;
    severity: Severity;
    description: string;
    cvssScore: number;
  }>;
}

const SERVICE_SIGNATURES: ServiceSignature[] = [
  {
    name: "SSH",
    defaultPorts: [22, 2222],
    bannerPattern: /SSH-[\d.]+-(OpenSSH[_\s]*([\d.]+[a-z\d]*)|dropbear[_\s]*([\d.]+)|libssh[_\s]*([\d.]+))/i,
    probe: null, // SSH servers send banner first
    knownVulnerableVersions: [
      {
        versionPattern: /OpenSSH[_\s]*([0-7]\.\d|8\.[0-7]($|p|[^0-9]))/i,
        cveId: "CVE-2023-38408",
        severity: Severity.High,
        description: "OpenSSH versions before 9.3p2 are vulnerable to PKCS#11 remote code execution via the ssh-agent forwarding feature.",
        cvssScore: 9.8,
      },
      {
        versionPattern: /OpenSSH[_\s]*([0-6]\.\d|7\.[0-6]($|p|[^0-9]))/i,
        cveId: "CVE-2020-15778",
        severity: Severity.High,
        description: "OpenSSH before 8.0 allows remote attackers to execute arbitrary commands via shell metacharacters in scp.",
        cvssScore: 7.8,
      },
    ],
  },
  {
    name: "FTP",
    defaultPorts: [21],
    bannerPattern: /(?:220[- ]).*?((?:vsftpd|ProFTPD|Pure-FTPd|FileZilla Server|Microsoft FTP Service)[/ ]*([\d.]+)?)/i,
    probe: null,
    knownVulnerableVersions: [
      {
        versionPattern: /vsftpd[/ ]*2\.3\.4/i,
        cveId: "CVE-2011-2523",
        severity: Severity.Critical,
        description: "vsftpd 2.3.4 contains a backdoor that opens a shell on port 6200 when triggered by a specific username pattern.",
        cvssScore: 10.0,
      },
      {
        versionPattern: /ProFTPD[/ ]*1\.3\.[0-5]/i,
        cveId: "CVE-2019-12815",
        severity: Severity.Critical,
        description: "ProFTPD before 1.3.6 allows arbitrary file copy due to insufficient access control in mod_copy.",
        cvssScore: 9.8,
      },
    ],
  },
  {
    name: "SMTP",
    defaultPorts: [25, 587, 465],
    bannerPattern: /(?:220[- ]).*?((?:Postfix|Exim|sendmail|Microsoft ESMTP|Dovecot|hMailServer)[/ ]*([\d.]+)?)/i,
    probe: null,
    knownVulnerableVersions: [
      {
        versionPattern: /Exim[/ ]*4\.([0-8]\d|9[0-3])($|[^0-9])/i,
        cveId: "CVE-2019-10149",
        severity: Severity.Critical,
        description: "Exim before 4.92 allows remote command execution as root via a crafted recipient address.",
        cvssScore: 9.8,
      },
    ],
  },
  {
    name: "HTTP",
    defaultPorts: [80, 8080, 8000, 8888],
    bannerPattern: /(?:Server:\s*)((?:Apache|nginx|Microsoft-IIS|lighttpd|LiteSpeed|Caddy|Tomcat|Jetty)[/ ]*([\d.]+)?)/i,
    probe: Buffer.from("HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"),
    knownVulnerableVersions: [
      {
        versionPattern: /Apache[/ ]*2\.4\.(0|[1-4]\d($|[^0-9]))/i,
        cveId: "CVE-2021-41773",
        severity: Severity.Critical,
        description: "Apache HTTP Server 2.4.49 and 2.4.50 have a path traversal vulnerability that allows reading files and potentially RCE.",
        cvssScore: 9.8,
      },
      {
        versionPattern: /nginx[/ ]*(0\.\d|1\.[0-9]($|[^0-9])|1\.1[0-7]($|[^0-9]))/i,
        cveId: "CVE-2021-23017",
        severity: Severity.High,
        description: "nginx before 1.21.0 has a DNS resolver vulnerability that can be exploited for remote code execution.",
        cvssScore: 7.7,
      },
    ],
  },
  {
    name: "HTTPS",
    defaultPorts: [443, 8443],
    bannerPattern: /(?:Server:\s*)((?:Apache|nginx|Microsoft-IIS|lighttpd|LiteSpeed|Caddy|Tomcat|Jetty)[/ ]*([\d.]+)?)/i,
    probe: null, // Handled by SSL/TLS scanner primarily
    knownVulnerableVersions: [],
  },
  {
    name: "MySQL",
    defaultPorts: [3306],
    bannerPattern: /([\d.]+).*?MySQL|mysql_native_password|MariaDB/i,
    probe: null, // MySQL server sends greeting packet
    knownVulnerableVersions: [
      {
        versionPattern: /5\.[0-6]\./i,
        cveId: "CVE-2012-2122",
        severity: Severity.High,
        description: "MySQL versions before 5.7 have multiple known authentication bypass and privilege escalation vulnerabilities.",
        cvssScore: 7.5,
      },
    ],
  },
  {
    name: "PostgreSQL",
    defaultPorts: [5432],
    bannerPattern: /PostgreSQL\s*([\d.]+)|FATAL|authentication/i,
    probe: Buffer.from("\x00\x00\x00\x08\x04\xd2\x16\x2f"), // SSL negotiation request
    knownVulnerableVersions: [
      {
        versionPattern: /PostgreSQL\s*(9\.[0-5]|10\.[0-9]($|[^0-9])|11\.[0-6]($|[^0-9]))/i,
        cveId: "CVE-2019-10164",
        severity: Severity.High,
        description: "PostgreSQL before 11.4 allows stack buffer overflow via large passwords.",
        cvssScore: 8.8,
      },
    ],
  },
  {
    name: "Redis",
    defaultPorts: [6379],
    bannerPattern: /redis_version:([\d.]+)|\+PONG|ERR.*Redis|-DENIED/i,
    probe: Buffer.from("PING\r\n"),
    knownVulnerableVersions: [
      {
        versionPattern: /redis_version:([0-5]\.|6\.[0-1]($|[^0-9]))/i,
        cveId: "CVE-2022-0543",
        severity: Severity.Critical,
        description: "Redis before 6.2.7 on Debian/Ubuntu allows Lua sandbox escape leading to remote code execution.",
        cvssScore: 10.0,
      },
    ],
  },
  {
    name: "MongoDB",
    defaultPorts: [27017],
    bannerPattern: /MongoDB|ismaster|isMaster|maxWireVersion/i,
    probe: Buffer.from([
      0x41, 0x00, 0x00, 0x00, // messageLength
      0x01, 0x00, 0x00, 0x00, // requestID
      0x00, 0x00, 0x00, 0x00, // responseTo
      0xd4, 0x07, 0x00, 0x00, // opCode: OP_QUERY
      0x00, 0x00, 0x00, 0x00, // flags
      0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // "admin.$cmd"
      0x00, 0x00, 0x00, 0x00, // numberToSkip
      0x01, 0x00, 0x00, 0x00, // numberToReturn
      0x14, 0x00, 0x00, 0x00, // BSON document size
      0x10,                   // type: int32
      0x69, 0x73, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, // "ismaster"
      0x01, 0x00, 0x00, 0x00, // value: 1
      0x00,                   // terminator
    ]),
    knownVulnerableVersions: [],
  },
  {
    name: "Memcached",
    defaultPorts: [11211],
    bannerPattern: /STAT version ([\d.]+)|VERSION ([\d.]+)/i,
    probe: Buffer.from("version\r\n"),
    knownVulnerableVersions: [
      {
        versionPattern: /(?:1\.[0-4]\.|1\.5\.[0-5]($|[^0-9]))/i,
        cveId: "CVE-2018-1000115",
        severity: Severity.High,
        description: "Memcached before 1.5.6 allows DDoS amplification attacks via the UDP protocol.",
        cvssScore: 7.5,
      },
    ],
  },
  {
    name: "RabbitMQ",
    defaultPorts: [5672, 15672],
    bannerPattern: /RabbitMQ|AMQP/i,
    probe: Buffer.from("AMQP\x00\x00\x09\x01"),
    knownVulnerableVersions: [],
  },
  {
    name: "Elasticsearch",
    defaultPorts: [9200, 9300],
    bannerPattern: /elasticsearch|"cluster_name"|"version".*?"number"\s*:\s*"([\d.]+)"/i,
    probe: Buffer.from("GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"),
    knownVulnerableVersions: [
      {
        versionPattern: /"number"\s*:\s*"([0-6]\.|7\.[0-9]($|[^0-9])|7\.1[0-3]($|[^0-9]))"/i,
        cveId: "CVE-2021-22145",
        severity: Severity.Medium,
        description: "Elasticsearch before 7.13.4 has an information disclosure vulnerability that can expose sensitive system information.",
        cvssScore: 6.5,
      },
    ],
  },
];

const CONNECTION_TIMEOUT_MS = 8_000;
const BANNER_READ_TIMEOUT_MS = 5_000;

// ---------------------------------------------------------------------------
// ServiceEnumerator
// ---------------------------------------------------------------------------

export class ServiceEnumerator implements ScanModule {
  readonly name = "network:service-enum";

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const { hostname } = this.parseTarget(target);
    const ports = (options.ports as number[]) ?? this.getDefaultPorts();

    log.info({ hostname, portCount: ports.length }, "Starting service enumeration");

    for (const port of ports) {
      // Check if port is open
      const isOpen = await this.isPortOpen(hostname, port);
      if (!isOpen) continue;

      log.debug({ hostname, port }, "Port is open, grabbing banner");

      // Find matching service signature for this port
      const matchingServices = SERVICE_SIGNATURES.filter(
        (s) => s.defaultPorts.includes(port),
      );

      // Also try all services if no default port match
      const servicesToTry = matchingServices.length > 0
        ? matchingServices
        : SERVICE_SIGNATURES;

      for (const service of servicesToTry) {
        const banner = await this.grabBanner(hostname, port, service.probe);
        if (!banner) continue;

        // Try to match the banner against the service signature
        const bannerMatch = service.bannerPattern.exec(banner);
        if (!bannerMatch) continue;

        const detectedService = bannerMatch[1] ?? service.name;
        const detectedVersion = bannerMatch[2] ?? bannerMatch[3] ?? "unknown";

        log.info(
          { hostname, port, service: detectedService, version: detectedVersion },
          "Service identified",
        );

        // Report the service discovery as an informational finding
        yield this.createFinding(
          `${service.name} Service Detected on Port ${port}`,
          `Detected ${detectedService} (version: ${detectedVersion}) running on ${hostname}:${port}. Banner: ${this.sanitizeBanner(banner)}`,
          Severity.Info,
          target,
          `${hostname}:${port}`,
          "CWE-200",
          0.0,
          85,
          {
            service: service.name,
            detectedService,
            version: detectedVersion,
            port,
            banner: this.sanitizeBanner(banner),
          },
        );

        // Check for known vulnerable versions
        for (const knownVuln of service.knownVulnerableVersions) {
          if (knownVuln.versionPattern.test(banner)) {
            yield this.createFinding(
              `${knownVuln.cveId}: Vulnerable ${service.name} Version on Port ${port}`,
              `${knownVuln.description}\n\nDetected version: ${detectedService} ${detectedVersion} on ${hostname}:${port}.`,
              knownVuln.severity,
              target,
              `${hostname}:${port}`,
              "CWE-1104",
              knownVuln.cvssScore,
              80,
              {
                cveId: knownVuln.cveId,
                service: service.name,
                version: detectedVersion,
                port,
              },
            );
          }
        }

        // Check for version disclosure in server header (information leakage)
        if (detectedVersion !== "unknown" && service.name === "HTTP") {
          yield this.createFinding(
            `HTTP Server Version Disclosure on Port ${port}`,
            `The HTTP server on ${hostname}:${port} discloses its version (${detectedService}) in the Server header. Version information helps attackers identify applicable exploits.`,
            Severity.Low,
            target,
            `${hostname}:${port}`,
            "CWE-200",
            3.7,
            80,
            { serverHeader: detectedService, version: detectedVersion },
          );
        }

        break; // Found a matching service, move to next port
      }
    }

    log.info({ hostname }, "Service enumeration complete");
  }

  // -------------------------------------------------------------------------
  // Port Scanning
  // -------------------------------------------------------------------------

  /**
   * Quick TCP connect check to determine if a port is open.
   */
  private isPortOpen(hostname: string, port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = connect({ host: hostname, port, timeout: CONNECTION_TIMEOUT_MS });

      socket.on("connect", () => {
        socket.destroy();
        resolve(true);
      });

      socket.on("error", () => {
        socket.destroy();
        resolve(false);
      });

      socket.on("timeout", () => {
        socket.destroy();
        resolve(false);
      });
    });
  }

  // -------------------------------------------------------------------------
  // Banner Grabbing
  // -------------------------------------------------------------------------

  /**
   * Grab a service banner from an open port.
   * Sends a probe if specified, otherwise waits for the server to speak first.
   */
  private grabBanner(
    hostname: string,
    port: number,
    probe: Buffer | null,
  ): Promise<string | null> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      let resolved = false;

      const done = (result: string | null) => {
        if (resolved) return;
        resolved = true;
        socket.destroy();
        resolve(result);
      };

      const socket: Socket = connect({ host: hostname, port, timeout: CONNECTION_TIMEOUT_MS });

      socket.on("connect", () => {
        if (probe) {
          // Replace 'target' placeholder in HTTP probes with actual hostname
          const probeStr = probe.toString();
          if (probeStr.includes("target")) {
            socket.write(Buffer.from(probeStr.replace("target", hostname)));
          } else {
            socket.write(probe);
          }
        }

        // Set a timeout to wait for banner data
        setTimeout(() => {
          if (chunks.length > 0) {
            done(Buffer.concat(chunks).toString("utf-8"));
          } else {
            done(null);
          }
        }, BANNER_READ_TIMEOUT_MS);
      });

      socket.on("data", (data) => {
        chunks.push(data);

        // If we have enough data, resolve immediately
        const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
        if (totalLen > 4096) {
          done(Buffer.concat(chunks).toString("utf-8"));
        }
      });

      socket.on("error", () => done(null));
      socket.on("timeout", () => done(chunks.length > 0 ? Buffer.concat(chunks).toString("utf-8") : null));
      socket.on("end", () => done(chunks.length > 0 ? Buffer.concat(chunks).toString("utf-8") : null));
    });
  }

  // -------------------------------------------------------------------------
  // Utility
  // -------------------------------------------------------------------------

  private parseTarget(target: string): { hostname: string } {
    let cleaned = target;
    if (cleaned.startsWith("https://")) cleaned = cleaned.slice(8);
    if (cleaned.startsWith("http://")) cleaned = cleaned.slice(7);
    const pathIndex = cleaned.indexOf("/");
    if (pathIndex !== -1) cleaned = cleaned.slice(0, pathIndex);
    const colonIndex = cleaned.lastIndexOf(":");
    if (colonIndex !== -1) cleaned = cleaned.slice(0, colonIndex);
    return { hostname: cleaned };
  }

  private getDefaultPorts(): number[] {
    const ports = new Set<number>();
    for (const sig of SERVICE_SIGNATURES) {
      for (const port of sig.defaultPorts) {
        ports.add(port);
      }
    }
    return [...ports].sort((a, b) => a - b);
  }

  /**
   * Sanitize a banner string for safe display (remove control characters, truncate).
   */
  private sanitizeBanner(banner: string): string {
    return banner
      .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "")
      .trim()
      .slice(0, 512);
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
      evidence: {
        description: title,
        extra,
      },
      remediation:
        severity === Severity.Info
          ? "Consider removing version information from service banners. For HTTP, configure the Server header to not disclose version details."
          : "Upgrade the service to the latest stable version. Apply all security patches. Consider restricting network access to this service.",
      references: [
        `https://cwe.mitre.org/data/definitions/${cweId.replace("CWE-", "")}.html`,
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
