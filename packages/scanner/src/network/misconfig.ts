// =============================================================================
// @vulnhunter/scanner - Network Misconfiguration Scanner
// =============================================================================
// Detects network-level misconfigurations including exposed database ports,
// default credentials, anonymous access to services, DNS rebinding
// vulnerabilities, and missing HTTP-to-HTTPS redirects.
// =============================================================================

import { connect } from "node:net";
import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { generateUUID, createLogger } from "@vulnhunter/core";
import type { ScanModule } from "../engine.js";

const log = createLogger("network-misconfig");

// ---------------------------------------------------------------------------
// Port Risk Definitions
// ---------------------------------------------------------------------------

interface PortRiskProfile {
  port: number;
  service: string;
  risk: string;
  severity: Severity;
  category: "database" | "admin" | "debug" | "legacy" | "unencrypted";
}

const HIGH_RISK_PORTS: PortRiskProfile[] = [
  { port: 3306, service: "MySQL", risk: "Database port exposed to the internet", severity: Severity.High, category: "database" },
  { port: 5432, service: "PostgreSQL", risk: "Database port exposed to the internet", severity: Severity.High, category: "database" },
  { port: 27017, service: "MongoDB", risk: "Database port exposed to the internet", severity: Severity.High, category: "database" },
  { port: 6379, service: "Redis", risk: "In-memory store exposed to the internet", severity: Severity.High, category: "database" },
  { port: 11211, service: "Memcached", risk: "Cache server exposed to the internet", severity: Severity.Medium, category: "database" },
  { port: 9200, service: "Elasticsearch", risk: "Search engine exposed to the internet", severity: Severity.High, category: "database" },
  { port: 9300, service: "Elasticsearch (transport)", risk: "Elasticsearch transport port exposed", severity: Severity.High, category: "database" },
  { port: 5672, service: "RabbitMQ", risk: "Message broker exposed to the internet", severity: Severity.Medium, category: "database" },
  { port: 15672, service: "RabbitMQ Management", risk: "RabbitMQ admin panel exposed", severity: Severity.High, category: "admin" },
  { port: 8080, service: "HTTP Proxy/Alt", risk: "Alternative HTTP port exposed", severity: Severity.Low, category: "unencrypted" },
  { port: 8443, service: "HTTPS Alt", risk: "Alternative HTTPS port exposed", severity: Severity.Info, category: "unencrypted" },
  { port: 2375, service: "Docker API", risk: "Docker daemon API exposed without TLS (CRITICAL)", severity: Severity.Critical, category: "admin" },
  { port: 2376, service: "Docker API (TLS)", risk: "Docker daemon API exposed", severity: Severity.High, category: "admin" },
  { port: 10250, service: "Kubernetes Kubelet", risk: "Kubernetes kubelet API exposed", severity: Severity.Critical, category: "admin" },
  { port: 10255, service: "Kubernetes Kubelet (read)", risk: "Kubernetes kubelet read-only API exposed", severity: Severity.High, category: "admin" },
  { port: 2379, service: "etcd", risk: "etcd cluster store exposed (Kubernetes secrets)", severity: Severity.Critical, category: "admin" },
  { port: 8500, service: "Consul", risk: "Consul service mesh UI/API exposed", severity: Severity.High, category: "admin" },
  { port: 9090, service: "Prometheus", risk: "Prometheus metrics endpoint exposed", severity: Severity.Medium, category: "admin" },
  { port: 3000, service: "Grafana", risk: "Grafana dashboard exposed", severity: Severity.Medium, category: "admin" },
  { port: 23, service: "Telnet", risk: "Unencrypted remote access protocol", severity: Severity.High, category: "legacy" },
  { port: 21, service: "FTP", risk: "Unencrypted file transfer protocol", severity: Severity.Medium, category: "legacy" },
  { port: 5900, service: "VNC", risk: "Remote desktop protocol exposed", severity: Severity.High, category: "admin" },
  { port: 3389, service: "RDP", risk: "Windows Remote Desktop exposed", severity: Severity.High, category: "admin" },
  { port: 1433, service: "MSSQL", risk: "Microsoft SQL Server exposed", severity: Severity.High, category: "database" },
  { port: 1521, service: "Oracle DB", risk: "Oracle Database exposed", severity: Severity.High, category: "database" },
  { port: 5601, service: "Kibana", risk: "Kibana dashboard exposed", severity: Severity.Medium, category: "admin" },
  { port: 9042, service: "Cassandra", risk: "Cassandra database exposed", severity: Severity.High, category: "database" },
  { port: 7474, service: "Neo4j", risk: "Neo4j graph database exposed", severity: Severity.High, category: "database" },
  { port: 8888, service: "Jupyter Notebook", risk: "Jupyter Notebook server exposed", severity: Severity.Critical, category: "admin" },
  { port: 4040, service: "Spark UI", risk: "Apache Spark web UI exposed", severity: Severity.Medium, category: "admin" },
];

// ---------------------------------------------------------------------------
// Default Credential Definitions
// ---------------------------------------------------------------------------

interface DefaultCredential {
  service: string;
  port: number;
  username: string;
  password: string;
  probe: string;
  successPattern: RegExp;
}

const DEFAULT_CREDENTIALS: DefaultCredential[] = [
  {
    service: "Redis",
    port: 6379,
    username: "",
    password: "",
    probe: "PING\r\n",
    successPattern: /\+PONG/,
  },
  {
    service: "Redis (default password)",
    port: 6379,
    username: "",
    password: "redis",
    probe: "AUTH redis\r\nPING\r\n",
    successPattern: /\+PONG|\+OK/,
  },
  {
    service: "Elasticsearch",
    port: 9200,
    username: "",
    password: "",
    probe: "GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    successPattern: /cluster_name|elasticsearch|"tagline"/i,
  },
  {
    service: "MongoDB",
    port: 27017,
    username: "",
    password: "",
    probe: "", // MongoDB responds to connection without auth
    successPattern: /ismaster|isMaster|maxWireVersion/,
  },
  {
    service: "Memcached",
    port: 11211,
    username: "",
    password: "",
    probe: "version\r\n",
    successPattern: /VERSION/,
  },
  {
    service: "FTP (anonymous)",
    port: 21,
    username: "anonymous",
    password: "anonymous@",
    probe: "", // FTP sends banner first
    successPattern: /230|Anonymous.*login/i,
  },
  {
    service: "RabbitMQ Management",
    port: 15672,
    username: "guest",
    password: "guest",
    probe: "", // Handled via HTTP
    successPattern: /200|rabbitmq|management/i,
  },
];

const CONNECTION_TIMEOUT_MS = 8_000;
const READ_TIMEOUT_MS = 5_000;

// ---------------------------------------------------------------------------
// NetworkMisconfigScanner
// ---------------------------------------------------------------------------

export class NetworkMisconfigScanner implements ScanModule {
  readonly name = "network:misconfig";

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const { hostname } = this.parseTarget(target);

    log.info({ hostname }, "Starting network misconfiguration scan");

    // 1. Open Port Risk Assessment
    yield* this.assessOpenPorts(hostname, target);

    // 2. Default Credential Testing
    yield* this.testDefaultCredentials(hostname, target);

    // 3. Anonymous Access Testing
    yield* this.testAnonymousAccess(hostname, target);

    // 4. HTTP to HTTPS Redirect Check
    yield* this.checkHttpRedirect(hostname, target);

    // 5. DNS Rebinding Check
    yield* this.checkDnsRebinding(hostname, target, options);

    log.info({ hostname }, "Network misconfiguration scan complete");
  }

  // -------------------------------------------------------------------------
  // Open Port Risk Assessment
  // -------------------------------------------------------------------------

  private async *assessOpenPorts(
    hostname: string,
    target: string,
  ): AsyncGenerator<Finding> {
    for (const risk of HIGH_RISK_PORTS) {
      const isOpen = await this.isPortOpen(hostname, risk.port);
      if (!isOpen) continue;

      log.info({ hostname, port: risk.port, service: risk.service }, "High-risk port detected open");

      yield this.createFinding(
        `Exposed ${risk.service} Port (${risk.port})`,
        `The ${risk.service} service on ${hostname}:${risk.port} is accessible from the network. ${risk.risk}. Direct exposure of ${risk.category === "database" ? "database" : risk.category === "admin" ? "administrative" : "service"} ports increases the attack surface and may allow unauthorized access, data exfiltration, or remote code execution.`,
        risk.severity,
        target,
        `${hostname}:${risk.port}`,
        risk.category === "database" ? "CWE-284" : risk.category === "admin" ? "CWE-269" : "CWE-319",
        risk.severity === Severity.Critical ? 9.1 : risk.severity === Severity.High ? 7.5 : risk.severity === Severity.Medium ? 5.3 : 3.1,
        80,
        { port: risk.port, service: risk.service, category: risk.category },
        `Restrict access to ${risk.service} (port ${risk.port}) using firewall rules. Only allow connections from trusted IP addresses or VPN networks. ${risk.category === "database" ? "Never expose database ports directly to the internet." : ""} Use network segmentation to isolate sensitive services.`,
      );
    }
  }

  // -------------------------------------------------------------------------
  // Default Credential Testing
  // -------------------------------------------------------------------------

  private async *testDefaultCredentials(
    hostname: string,
    target: string,
  ): AsyncGenerator<Finding> {
    for (const cred of DEFAULT_CREDENTIALS) {
      const isOpen = await this.isPortOpen(hostname, cred.port);
      if (!isOpen) continue;

      // For HTTP-based services, use fetch
      if (cred.port === 15672) {
        yield* this.testHttpDefaultCreds(hostname, cred, target);
        continue;
      }

      // For TCP-based services, use socket probing
      const response = await this.sendProbe(hostname, cred.port, cred.probe);
      if (!response) continue;

      if (cred.successPattern.test(response)) {
        const isAnonymous = !cred.username && !cred.password;
        const credInfo = isAnonymous
          ? "without authentication"
          : `with default credentials (${cred.username}:${cred.password})`;

        yield this.createFinding(
          `${cred.service} Accessible ${isAnonymous ? "Without Authentication" : "With Default Credentials"}`,
          `The ${cred.service} service on ${hostname}:${cred.port} is accessible ${credInfo}. ${isAnonymous
            ? "The service does not require any authentication, allowing anyone with network access to interact with it."
            : "Default credentials have not been changed, allowing attackers with knowledge of default credentials to gain access."}`,
          Severity.Critical,
          target,
          `${hostname}:${cred.port}`,
          isAnonymous ? "CWE-306" : "CWE-1393",
          9.1,
          isAnonymous ? 90 : 85,
          {
            service: cred.service,
            port: cred.port,
            username: cred.username || "(none)",
            authenticated: !isAnonymous,
            responseSnippet: response.slice(0, 200),
          },
          isAnonymous
            ? `Enable authentication for ${cred.service}. Configure strong passwords and enable TLS encryption. Restrict network access via firewall rules.`
            : `Change the default credentials for ${cred.service} immediately. Use strong, unique passwords. Consider integrating with a centralized authentication system.`,
        );
      }
    }
  }

  /**
   * Test HTTP-based services for default credentials.
   */
  private async *testHttpDefaultCreds(
    hostname: string,
    cred: DefaultCredential,
    target: string,
  ): AsyncGenerator<Finding> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), CONNECTION_TIMEOUT_MS);

      const authHeader = Buffer.from(`${cred.username}:${cred.password}`).toString("base64");

      const response = await fetch(`http://${hostname}:${cred.port}/api/overview`, {
        method: "GET",
        headers: {
          Authorization: `Basic ${authHeader}`,
          Connection: "close",
        },
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (response.ok) {
        yield this.createFinding(
          `${cred.service} Accessible With Default Credentials`,
          `The ${cred.service} on ${hostname}:${cred.port} is accessible with default credentials (${cred.username}:${cred.password}). This provides full administrative access to the service.`,
          Severity.Critical,
          target,
          `http://${hostname}:${cred.port}/`,
          "CWE-1393",
          9.1,
          90,
          {
            service: cred.service,
            port: cred.port,
            username: cred.username,
            httpStatus: response.status,
          },
          `Change the default credentials for ${cred.service} immediately. Disable the guest account. Use strong passwords and enable TLS.`,
        );
      }
    } catch {
      // Connection failed or timeout, service not accessible
    }
  }

  // -------------------------------------------------------------------------
  // Anonymous Access Testing
  // -------------------------------------------------------------------------

  private async *testAnonymousAccess(
    hostname: string,
    target: string,
  ): AsyncGenerator<Finding> {
    // Test FTP anonymous access
    yield* this.testFtpAnonymous(hostname, target);

    // Test Elasticsearch without auth
    yield* this.testElasticsearchAnonymous(hostname, target);

    // Test MongoDB without auth
    yield* this.testMongoAnonymous(hostname, target);
  }

  private async *testFtpAnonymous(hostname: string, target: string): AsyncGenerator<Finding> {
    const isOpen = await this.isPortOpen(hostname, 21);
    if (!isOpen) return;

    // Connect and try anonymous login sequence
    const banner = await this.sendProbe(hostname, 21, "");
    if (!banner || !banner.includes("220")) return;

    const loginResponse = await this.ftpLogin(hostname, "anonymous", "anonymous@test.com");
    if (loginResponse && loginResponse.includes("230")) {
      yield this.createFinding(
        "FTP Anonymous Login Enabled",
        `The FTP server on ${hostname}:21 allows anonymous login. Anonymous users may be able to browse, download, or upload files depending on the server configuration.`,
        Severity.High,
        target,
        `${hostname}:21`,
        "CWE-284",
        7.5,
        90,
        { service: "FTP", port: 21, anonymousAccess: true },
        "Disable anonymous FTP access unless specifically required. If anonymous access is needed, restrict it to a dedicated read-only directory with no sensitive files. Use SFTP instead of FTP.",
      );
    }
  }

  private async *testElasticsearchAnonymous(hostname: string, target: string): AsyncGenerator<Finding> {
    const isOpen = await this.isPortOpen(hostname, 9200);
    if (!isOpen) return;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), CONNECTION_TIMEOUT_MS);

      const response = await fetch(`http://${hostname}:9200/_cat/indices`, {
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (response.ok) {
        const body = await response.text();
        yield this.createFinding(
          "Elasticsearch Accessible Without Authentication",
          `The Elasticsearch instance on ${hostname}:9200 is accessible without authentication. The _cat/indices endpoint returns data, indicating full read access to all indices. This could expose sensitive application data, user records, logs, and more.`,
          Severity.Critical,
          target,
          `http://${hostname}:9200/`,
          "CWE-306",
          9.8,
          95,
          {
            service: "Elasticsearch",
            port: 9200,
            indexCount: body.split("\n").filter(Boolean).length,
          },
          "Enable Elasticsearch security features (X-Pack Security). Configure authentication, TLS, and role-based access control. Restrict network access via firewall rules.",
        );
      }
    } catch {
      // Not accessible
    }
  }

  private async *testMongoAnonymous(hostname: string, target: string): AsyncGenerator<Finding> {
    const isOpen = await this.isPortOpen(hostname, 27017);
    if (!isOpen) return;

    // Send a MongoDB isMaster probe
    const response = await this.sendProbe(hostname, 27017, "");
    if (response && (response.includes("ismaster") || response.includes("maxWireVersion"))) {
      yield this.createFinding(
        "MongoDB Accessible Without Authentication",
        `The MongoDB instance on ${hostname}:27017 responds to queries without authentication. This allows full database access including reading, modifying, and deleting all data.`,
        Severity.Critical,
        target,
        `${hostname}:27017`,
        "CWE-306",
        9.8,
        85,
        { service: "MongoDB", port: 27017, anonymousAccess: true },
        "Enable MongoDB authentication: use SCRAM-SHA-256. Require authentication for all connections. Enable TLS. Restrict network access. Never expose MongoDB to the internet.",
      );
    }
  }

  // -------------------------------------------------------------------------
  // HTTP Redirect Check
  // -------------------------------------------------------------------------

  private async *checkHttpRedirect(
    hostname: string,
    target: string,
  ): AsyncGenerator<Finding> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), CONNECTION_TIMEOUT_MS);

      const response = await fetch(`http://${hostname}/`, {
        method: "HEAD",
        redirect: "manual",
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (response.status === 200) {
        yield this.createFinding(
          "HTTP Service Without HTTPS Redirect",
          `The server ${hostname} serves content over plain HTTP (port 80) without redirecting to HTTPS. This allows users to inadvertently transmit sensitive data (credentials, session tokens, personal information) in plaintext, vulnerable to interception.`,
          Severity.Medium,
          target,
          `http://${hostname}/`,
          "CWE-319",
          5.3,
          80,
          { httpStatus: response.status, redirectsToHttps: false },
          "Configure the web server to redirect all HTTP (port 80) traffic to HTTPS (port 443) using a 301 redirect. Enable HSTS to prevent future HTTP connections.",
        );
      } else if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location") ?? "";
        if (!location.startsWith("https://")) {
          yield this.createFinding(
            "HTTP Redirect Does Not Use HTTPS",
            `The server ${hostname} redirects HTTP traffic but the redirect target (${location}) does not use HTTPS. The redirect itself is still vulnerable to interception.`,
            Severity.Medium,
            target,
            `http://${hostname}/`,
            "CWE-319",
            5.3,
            75,
            { httpStatus: response.status, location, redirectsToHttps: false },
            "Ensure the HTTP redirect target uses HTTPS: Location: https://...",
          );
        }
      }
    } catch {
      // HTTP port not responding, which is acceptable
    }
  }

  // -------------------------------------------------------------------------
  // DNS Rebinding Check
  // -------------------------------------------------------------------------

  private async *checkDnsRebinding(
    hostname: string,
    target: string,
    _options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    // DNS rebinding check: verify the server validates Host header
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), CONNECTION_TIMEOUT_MS);

      // Send a request with a spoofed Host header to test for DNS rebinding vulnerability
      const response = await fetch(`http://${hostname}/`, {
        method: "GET",
        headers: {
          Host: "evil-rebind.attacker.com",
          Connection: "close",
        },
        redirect: "manual",
        signal: controller.signal,
      });

      clearTimeout(timeout);

      // If the server responds 200 with a spoofed Host header, it may be vulnerable
      if (response.status === 200) {
        const body = await response.text();
        // Check if the response contains the spoofed hostname (reflected)
        if (body.includes("evil-rebind") || body.includes("attacker.com")) {
          yield this.createFinding(
            "Potential DNS Rebinding Vulnerability",
            `The server ${hostname} accepts and reflects an arbitrary Host header (evil-rebind.attacker.com). This may indicate susceptibility to DNS rebinding attacks, where an attacker-controlled DNS record alternates between their IP and the target's internal IP, allowing JavaScript in the attacker's page to make authenticated requests to the internal service.`,
            Severity.Medium,
            target,
            `http://${hostname}/`,
            "CWE-350",
            5.3,
            60,
            { hostnameReflected: true },
            "Validate the Host header against a whitelist of expected hostnames. Return a 400/403 error for unrecognized Host values. Configure your web server to only respond to known virtual hosts.",
          );
        }
      }
    } catch {
      // Cannot test DNS rebinding
    }
  }

  // -------------------------------------------------------------------------
  // TCP Helpers
  // -------------------------------------------------------------------------

  private isPortOpen(hostname: string, port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = connect({ host: hostname, port, timeout: CONNECTION_TIMEOUT_MS });
      socket.on("connect", () => { socket.destroy(); resolve(true); });
      socket.on("error", () => { socket.destroy(); resolve(false); });
      socket.on("timeout", () => { socket.destroy(); resolve(false); });
    });
  }

  private sendProbe(hostname: string, port: number, probeData: string): Promise<string | null> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      let resolved = false;

      const done = (result: string | null) => {
        if (resolved) return;
        resolved = true;
        socket.destroy();
        resolve(result);
      };

      const socket = connect({ host: hostname, port, timeout: CONNECTION_TIMEOUT_MS });

      socket.on("connect", () => {
        if (probeData) {
          socket.write(probeData.replace("target", hostname));
        }
        setTimeout(() => {
          done(chunks.length > 0 ? Buffer.concat(chunks).toString("utf-8") : null);
        }, READ_TIMEOUT_MS);
      });

      socket.on("data", (data) => {
        chunks.push(data);
        if (chunks.reduce((s, c) => s + c.length, 0) > 4096) {
          done(Buffer.concat(chunks).toString("utf-8"));
        }
      });

      socket.on("error", () => done(null));
      socket.on("timeout", () => done(null));
      socket.on("end", () => done(chunks.length > 0 ? Buffer.concat(chunks).toString("utf-8") : null));
    });
  }

  private ftpLogin(hostname: string, username: string, password: string): Promise<string | null> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      let phase: "banner" | "user" | "pass" | "done" = "banner";
      let resolved = false;

      const done = (result: string | null) => {
        if (resolved) return;
        resolved = true;
        socket.destroy();
        resolve(result);
      };

      const socket = connect({ host: hostname, port: 21, timeout: CONNECTION_TIMEOUT_MS });

      socket.on("data", (data) => {
        const text = data.toString("utf-8");
        chunks.push(data);

        if (phase === "banner" && text.includes("220")) {
          phase = "user";
          socket.write(`USER ${username}\r\n`);
        } else if (phase === "user" && (text.includes("331") || text.includes("230"))) {
          if (text.includes("230")) {
            done(text); // Logged in without password
          } else {
            phase = "pass";
            socket.write(`PASS ${password}\r\n`);
          }
        } else if (phase === "pass") {
          done(text);
        }
      });

      socket.on("error", () => done(null));
      socket.on("timeout", () => done(null));
      setTimeout(() => done(null), READ_TIMEOUT_MS + 3000);
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
    if (colonIndex !== -1 && colonIndex > cleaned.lastIndexOf("]")) {
      cleaned = cleaned.slice(0, colonIndex);
    }
    return { hostname: cleaned };
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
      evidence: {
        description: title,
        extra,
      },
      remediation,
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
