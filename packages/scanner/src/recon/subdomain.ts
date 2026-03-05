// =============================================================================
// @vulnhunter/scanner - Subdomain Enumeration Module
// =============================================================================
// Discovers subdomains through multiple techniques:
//   1. DNS brute-force using a built-in wordlist of 500+ common subdomains
//   2. Certificate Transparency log querying via crt.sh
//   3. Web Archive (web.archive.org) subdomain discovery
//   4. DNS resolution validation of every discovered subdomain
// =============================================================================

import { randomBytes } from "crypto";
import { Resolver } from "dns/promises";
import type { ScanModule } from "../engine.js";
import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { createLogger } from "@vulnhunter/core";

const log = createLogger("recon:subdomain");

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
// Built-in subdomain wordlist (500+ entries)
// ---------------------------------------------------------------------------
const SUBDOMAIN_WORDLIST: string[] = [
  // Infrastructure & hosting
  "www", "www1", "www2", "www3", "www4", "www5",
  "mail", "mail1", "mail2", "mail3", "smtp", "pop", "pop3", "imap",
  "email", "webmail", "exchange", "owa", "outlook",
  "ftp", "ftp1", "ftp2", "sftp",
  "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
  "mx", "mx1", "mx2", "mx3",
  // Web & API
  "api", "api1", "api2", "api3", "api-v1", "api-v2",
  "rest", "graphql", "gql", "grpc",
  "app", "apps", "application", "web", "webapp", "portal",
  "mobile", "m", "mobi",
  "cdn", "cdn1", "cdn2", "static", "assets", "media", "images", "img",
  "files", "download", "downloads", "upload", "uploads",
  // Development & staging
  "dev", "dev1", "dev2", "dev3", "develop", "development",
  "stage", "staging", "stg", "stag",
  "test", "test1", "test2", "test3", "testing", "qa", "qa1", "qa2",
  "uat", "preprod", "pre-prod", "pre", "preview",
  "sandbox", "demo", "beta", "alpha", "canary",
  "local", "localhost",
  // CI/CD & DevOps
  "ci", "cd", "build", "builds", "deploy", "deployment",
  "jenkins", "gitlab", "github", "bitbucket", "bamboo",
  "drone", "circleci", "travis", "teamcity",
  "docker", "k8s", "kubernetes", "rancher", "nomad",
  "ansible", "puppet", "chef", "terraform",
  "registry", "repo", "repository", "git", "svn",
  "artifactory", "nexus", "harbor", "quay",
  // Monitoring & observability
  "monitor", "monitoring", "nagios", "zabbix", "grafana",
  "prometheus", "datadog", "newrelic", "splunk",
  "kibana", "elastic", "elasticsearch", "logstash",
  "sentry", "pagerduty", "opsgenie",
  "status", "health", "healthcheck", "heartbeat",
  "metrics", "stats", "analytics",
  // Admin & management
  "admin", "admin1", "admin2", "administrator",
  "manage", "manager", "management",
  "panel", "cpanel", "whm", "plesk", "webmin",
  "console", "dashboard", "control",
  "cms", "wp", "wordpress", "joomla", "drupal",
  "phpmyadmin", "pma", "adminer", "pgadmin",
  // Database & cache
  "db", "db1", "db2", "db3", "database",
  "mysql", "postgres", "postgresql", "pgsql",
  "mongo", "mongodb", "redis", "memcache", "memcached",
  "cassandra", "couchdb", "couchbase", "neo4j",
  "sql", "mssql", "oracle", "mariadb",
  "elastic", "solr", "sphinx",
  // Authentication & identity
  "auth", "auth0", "oauth", "sso", "login", "signin",
  "ldap", "ad", "directory", "identity", "iam",
  "keycloak", "okta", "saml", "cas",
  "accounts", "account", "signup", "register",
  // Communication
  "chat", "slack", "teams", "mattermost", "rocket",
  "irc", "xmpp", "jabber",
  "meet", "meeting", "conference", "zoom", "webex",
  "voice", "voip", "sip", "pbx", "asterisk",
  "forum", "forums", "community", "discuss", "discourse",
  // VPN & security
  "vpn", "vpn1", "vpn2", "openvpn", "wireguard",
  "ssl", "tls", "cert", "certs", "certificates",
  "proxy", "proxy1", "proxy2", "squid", "nginx",
  "waf", "firewall", "fw", "ids", "ips",
  "security", "sec", "soc", "csirt",
  // Cloud & storage
  "cloud", "aws", "azure", "gcp", "gce",
  "s3", "storage", "backup", "backups", "bak",
  "archive", "archives", "vault",
  "nas", "san", "nfs", "cifs", "smb",
  // Networking
  "gateway", "gw", "gw1", "router", "switch",
  "lb", "loadbalancer", "load-balancer", "haproxy",
  "edge", "node", "cluster",
  "intranet", "internal", "corp", "corporate",
  "extranet", "partner", "partners",
  "remote", "rdp", "citrix", "terminal",
  "wifi", "wireless", "ap",
  // E-commerce & business
  "shop", "store", "ecommerce", "cart", "checkout",
  "pay", "payment", "payments", "billing", "invoice",
  "crm", "erp", "sap", "salesforce",
  "hr", "helpdesk", "servicedesk", "jira", "zendesk",
  "support", "help", "ticket", "tickets",
  "docs", "documentation", "wiki", "confluence",
  "blog", "news", "press", "marketing",
  // Misc services
  "search", "es", "solr",
  "queue", "mq", "rabbitmq", "kafka", "activemq",
  "cache", "varnish",
  "cron", "scheduler", "jobs", "worker", "workers",
  "ws", "websocket", "wss", "socket",
  "notify", "notification", "notifications", "push",
  "feed", "rss", "atom",
  "map", "maps", "geo", "gis", "location",
  "video", "stream", "streaming", "live", "rtmp",
  "music", "audio", "podcast",
  // Subdomains for specific providers
  "autodiscover", "autoconfig", "lyncdiscover",
  "sip", "sipfed", "lync", "dialin",
  "adfs", "fs", "sts",
  "_dmarc", "_domainkey",
  // Internationalization
  "en", "es", "fr", "de", "it", "pt", "nl", "ru", "cn", "jp", "kr",
  "uk", "us", "eu", "asia", "global", "intl",
  // Legacy & migration
  "old", "legacy", "v1", "v2", "v3", "new",
  "origin", "primary", "secondary",
  "temp", "tmp", "scratch",
  // Numbered hosts
  "host", "host1", "host2", "host3",
  "server", "server1", "server2", "server3",
  "node1", "node2", "node3",
  "web1", "web2", "web3",
  "app1", "app2", "app3",
  "sv", "sv1", "sv2", "sv3",
  "dc", "dc1", "dc2", "dc3",
  // More infrastructure
  "mx0", "relay", "relay1", "relay2",
  "bastion", "jump", "jumpbox",
  "log", "logs", "syslog", "rsyslog",
  "ntp", "time", "clock",
  "snap", "snapshot",
  "bmc", "ipmi", "ilo", "idrac", "imm",
  // Development tools
  "sonar", "sonarqube", "lint",
  "swagger", "redoc", "openapi",
  "postman", "insomnia",
  "storybook", "chromatic",
  // More security
  "scan", "scanner", "pentest",
  "bounty", "bugbounty",
  "honeypot", "trap",
  // More cloud-native
  "istio", "envoy", "consul", "vault",
  "argo", "argocd", "flux",
  "helm", "chart", "charts",
  "operator", "etcd",
  // Data & analytics
  "data", "bigdata", "warehouse", "dw", "dwh",
  "bi", "tableau", "looker", "superset",
  "airflow", "dag", "pipeline",
  "ml", "ai", "model", "inference",
  "notebook", "jupyter", "lab",
  // Content
  "cms", "content", "editor",
  "image", "img1", "img2", "photo", "photos",
  "thumb", "thumbnail", "resize",
  "fonts", "font",
  "css", "js", "script", "scripts",
  // Government & edu patterns
  "www2", "portal2",
  "secure", "safe",
  "prod", "production",
  "reports", "report", "reporting",
  "survey", "surveys", "forms", "form",
  "vote", "poll", "polls",
  "calendar", "cal", "schedule",
  "event", "events",
  "training", "learn", "learning", "lms", "moodle",
  "library", "lib",
  "research", "lab", "labs",
  // Additional patterns often found
  "api-gateway", "api-gw", "api-proxy",
  "backend", "be", "frontend", "fe",
  "microservice", "service", "services", "svc",
  "internal-api", "external-api", "public-api", "private-api",
  "staging-api", "dev-api", "test-api",
  "www-staging", "www-dev", "www-test",
  "admin-api", "admin-panel",
  "core", "platform",
  "integration", "integrations", "webhook", "webhooks",
  "oauth2", "token", "tokens", "session",
  "config", "configuration",
  "feature", "features", "flag", "flags",
  "ab", "experiment", "experiments",
  "preview-app", "review-app",
  "canary-api", "shadow",
];

// ---------------------------------------------------------------------------
// SubdomainEnumerator
// ---------------------------------------------------------------------------

export class SubdomainEnumerator implements ScanModule {
  readonly name = "recon:subdomain";

  private resolver!: Resolver;
  private timeoutMs = 5000;
  private maxConcurrency = 20;
  private userAgent = "VulnHunter/1.0 (Security Scanner)";

  async init(
    _target: string,
    options: Record<string, unknown>,
  ): Promise<void> {
    this.resolver = new Resolver();
    // Use Google and Cloudflare DNS for reliability
    this.resolver.setServers(["8.8.8.8", "1.1.1.1", "8.8.4.4"]);

    if (typeof options.requestTimeoutMs === "number") {
      this.timeoutMs = options.requestTimeoutMs;
    }
    if (typeof options.maxConcurrency === "number") {
      this.maxConcurrency = options.maxConcurrency;
    }
    if (typeof options.userAgent === "string") {
      this.userAgent = options.userAgent;
    }

    log.info("SubdomainEnumerator initialized");
  }

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    // Normalize target to a bare domain (strip protocol, path, port)
    const domain = this.extractDomain(target);
    log.info({ domain }, "Starting subdomain enumeration");

    // Collect subdomains from all sources into a deduplicated set
    const discovered = new Set<string>();

    // --- Source 1: DNS brute-force ---
    log.info({ domain, wordlistSize: SUBDOMAIN_WORDLIST.length }, "Starting DNS brute-force");
    const bruteForceResults = await this.dnsbruteForce(domain);
    for (const sub of bruteForceResults) {
      discovered.add(sub.toLowerCase());
    }
    log.info(
      { domain, found: bruteForceResults.length },
      "DNS brute-force complete",
    );

    // --- Source 2: Certificate Transparency (crt.sh) ---
    log.info({ domain }, "Querying Certificate Transparency logs");
    const ctResults = await this.queryCertificateTransparency(domain);
    for (const sub of ctResults) {
      discovered.add(sub.toLowerCase());
    }
    log.info({ domain, found: ctResults.length }, "CT log query complete");

    // --- Source 3: Web Archive ---
    log.info({ domain }, "Querying Web Archive");
    const archiveResults = await this.queryWebArchive(domain);
    for (const sub of archiveResults) {
      discovered.add(sub.toLowerCase());
    }
    log.info(
      { domain, found: archiveResults.length },
      "Web Archive query complete",
    );

    log.info(
      { domain, totalUnique: discovered.size },
      "Subdomain collection complete, validating DNS",
    );

    // --- DNS resolution validation ---
    const validated = await this.validateSubdomains(
      Array.from(discovered),
      domain,
    );

    log.info(
      { domain, validated: validated.length },
      "DNS validation complete",
    );

    // Yield each validated subdomain as a Finding
    for (const entry of validated) {
      yield this.createFinding(domain, entry.subdomain, entry.ips);
    }
  }

  async cleanup(): Promise<void> {
    // Resolver has no explicit close in Node.js; just let GC handle it
    log.info("SubdomainEnumerator cleanup complete");
  }

  // -------------------------------------------------------------------------
  // DNS Brute-Force
  // -------------------------------------------------------------------------

  /**
   * Resolve each candidate subdomain against the target domain using batched
   * concurrent DNS lookups. Returns the list of subdomains that successfully
   * resolved.
   */
  private async dnsbruteForce(domain: string): Promise<string[]> {
    const found: string[] = [];
    const candidates = SUBDOMAIN_WORDLIST.map((w) => `${w}.${domain}`);

    // Process in batches to respect concurrency limits
    for (let i = 0; i < candidates.length; i += this.maxConcurrency) {
      const batch = candidates.slice(i, i + this.maxConcurrency);
      const results = await Promise.allSettled(
        batch.map((fqdn) => this.resolveWithTimeout(fqdn)),
      );

      for (let j = 0; j < results.length; j++) {
        const result = results[j];
        if (result.status === "fulfilled" && result.value.length > 0) {
          found.push(batch[j]);
        }
      }
    }

    return found;
  }

  /**
   * Resolve a hostname with a timeout.
   */
  private async resolveWithTimeout(hostname: string): Promise<string[]> {
    return new Promise<string[]>((resolve) => {
      const timer = setTimeout(() => resolve([]), this.timeoutMs);

      this.resolver
        .resolve4(hostname)
        .then((addresses) => {
          clearTimeout(timer);
          resolve(addresses);
        })
        .catch(() => {
          clearTimeout(timer);
          resolve([]);
        });
    });
  }

  // -------------------------------------------------------------------------
  // Certificate Transparency
  // -------------------------------------------------------------------------

  /**
   * Query crt.sh for certificates issued for *.domain, extract unique
   * subdomain names.
   */
  private async queryCertificateTransparency(
    domain: string,
  ): Promise<string[]> {
    const subdomains: string[] = [];

    try {
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        this.timeoutMs * 2,
      );

      const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
      const response = await fetch(url, {
        signal: controller.signal,
        headers: { "User-Agent": this.userAgent },
      });

      clearTimeout(timeout);

      if (!response.ok) {
        log.warn(
          { status: response.status },
          "crt.sh returned non-OK status",
        );
        return subdomains;
      }

      const data = (await response.json()) as Array<{
        name_value: string;
        common_name?: string;
      }>;

      const seen = new Set<string>();
      for (const entry of data) {
        // name_value can contain newline-separated names
        const names = entry.name_value
          .split("\n")
          .map((n: string) => n.trim().toLowerCase())
          .filter(
            (n: string) => n.endsWith(`.${domain}`) || n === domain,
          );

        for (const name of names) {
          // Strip wildcard prefix
          const clean = name.replace(/^\*\./, "");
          if (!seen.has(clean)) {
            seen.add(clean);
            subdomains.push(clean);
          }
        }
      }
    } catch (error) {
      log.warn(
        {
          error:
            error instanceof Error ? error.message : String(error),
        },
        "Certificate Transparency query failed (non-fatal)",
      );
    }

    return subdomains;
  }

  // -------------------------------------------------------------------------
  // Web Archive
  // -------------------------------------------------------------------------

  /**
   * Query the Wayback Machine's CDX API for URLs under the target domain,
   * extract unique subdomains.
   */
  private async queryWebArchive(domain: string): Promise<string[]> {
    const subdomains: string[] = [];

    try {
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        this.timeoutMs * 3,
      );

      const url =
        `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&limit=5000`;
      const response = await fetch(url, {
        signal: controller.signal,
        headers: { "User-Agent": this.userAgent },
      });

      clearTimeout(timeout);

      if (!response.ok) {
        log.warn(
          { status: response.status },
          "Web Archive returned non-OK status",
        );
        return subdomains;
      }

      const data = (await response.json()) as string[][];
      const seen = new Set<string>();

      // First row is the header ["original"]
      for (let i = 1; i < data.length; i++) {
        const row = data[i];
        if (!row || row.length === 0) continue;
        try {
          const parsed = new URL(row[0]);
          const host = parsed.hostname.toLowerCase();
          if (
            (host.endsWith(`.${domain}`) || host === domain) &&
            !seen.has(host)
          ) {
            seen.add(host);
            subdomains.push(host);
          }
        } catch {
          // Invalid URL, skip
        }
      }
    } catch (error) {
      log.warn(
        {
          error:
            error instanceof Error ? error.message : String(error),
        },
        "Web Archive query failed (non-fatal)",
      );
    }

    return subdomains;
  }

  // -------------------------------------------------------------------------
  // DNS Validation
  // -------------------------------------------------------------------------

  /**
   * Resolve each discovered subdomain to confirm it actually has DNS records.
   * Returns only subdomains that successfully resolve.
   */
  private async validateSubdomains(
    subdomains: string[],
    _domain: string,
  ): Promise<Array<{ subdomain: string; ips: string[] }>> {
    const validated: Array<{ subdomain: string; ips: string[] }> = [];

    for (let i = 0; i < subdomains.length; i += this.maxConcurrency) {
      const batch = subdomains.slice(i, i + this.maxConcurrency);
      const results = await Promise.allSettled(
        batch.map(async (sub) => {
          const ips = await this.resolveWithTimeout(sub);
          return { subdomain: sub, ips };
        }),
      );

      for (const result of results) {
        if (
          result.status === "fulfilled" &&
          result.value.ips.length > 0
        ) {
          validated.push(result.value);
        }
      }
    }

    return validated;
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /**
   * Extract the base domain from a target string. Handles URLs, domains
   * with ports, etc.
   */
  private extractDomain(target: string): string {
    let domain = target;

    // If it looks like a URL, parse it
    if (domain.includes("://")) {
      try {
        const parsed = new URL(domain);
        domain = parsed.hostname;
      } catch {
        // Not a valid URL, try to strip protocol manually
        domain = domain.replace(/^[a-z]+:\/\//i, "");
      }
    }

    // Strip port if present
    domain = domain.split(":")[0];
    // Strip path if present
    domain = domain.split("/")[0];
    // Strip trailing dot
    domain = domain.replace(/\.$/, "");

    return domain.toLowerCase();
  }

  /**
   * Convert a validated subdomain into a Finding object.
   */
  private createFinding(
    parentDomain: string,
    subdomain: string,
    ips: string[],
  ): Finding {
    const now = new Date().toISOString();

    const vulnerability: Vulnerability = {
      id: uuid(),
      title: `Subdomain discovered: ${subdomain}`,
      description:
        `The subdomain ${subdomain} was discovered under ${parentDomain} and resolves to IP address(es): ${ips.join(", ")}. ` +
        `This information can be used to map the attack surface of the target.`,
      severity: Severity.Info,
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore: 0.0,
      target: parentDomain,
      endpoint: subdomain,
      evidence: {
        description: `DNS resolution confirmed for ${subdomain}`,
        extra: {
          resolvedIps: ips,
          parentDomain,
        },
      },
      remediation:
        "Review whether this subdomain should be publicly accessible. " +
        "Ensure it is covered by the security policy and is not exposing " +
        "sensitive services.",
      references: [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage",
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
        subdomain,
        ips,
        parentDomain,
      },
    };
  }
}
