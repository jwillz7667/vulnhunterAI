// =============================================================================
// @vulnhunter/scanner - Port Scanner Module
// =============================================================================
// TCP connect-scan on configurable port ranges with banner grabbing and
// service/version detection. Includes the top 1000 TCP ports by default.
// =============================================================================

import { randomBytes } from "crypto";
import * as net from "net";
import type { ScanModule } from "../engine.js";
import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { createLogger } from "@vulnhunter/core";

const log = createLogger("recon:port-scan");

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
// Top 1000 TCP ports (nmap default top-1000 order)
// ---------------------------------------------------------------------------
const TOP_1000_PORTS: number[] = [
  1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,
  80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,
  144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,
  340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,
  512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,
  631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,
  765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,
  981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,
  1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,
  1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,
  1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,
  1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,
  1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,
  1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,
  1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,
  1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,
  1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,
  1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,
  1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,
  1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,
  1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,
  1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,
  2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,
  2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,
  2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,
  2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,
  2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,
  2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,
  3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,
  3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,
  3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,
  3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,
  3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,
  4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,
  4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,
  5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,
  5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,
  5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,
  5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,
  5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,
  5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,
  6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,
  6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,
  6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,
  7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,
  7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,
  8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,
  8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,
  8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,
  8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,
  9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9443,
  9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,
  9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,
  10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,
  10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,
  13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,
  15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,
  18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,
  20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,
  27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,
  32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,
  32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,
  38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,
  49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,
  49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,
  50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,
  55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,
  63331,64623,64680,65000,65129,65389,
];

// ---------------------------------------------------------------------------
// Service fingerprints: regex patterns matched against banner data to
// identify the service and version running on a port.
// ---------------------------------------------------------------------------
interface ServiceSignature {
  name: string;
  pattern: RegExp;
  /** Extract version from the first capture group if present. */
  versionGroup?: number;
}

const SERVICE_SIGNATURES: ServiceSignature[] = [
  // SSH
  { name: "SSH", pattern: /^SSH-(\d+\.\d+)-(.+)/i, versionGroup: 2 },
  // FTP
  { name: "FTP", pattern: /^220[\s-].*(?:ftp|vsftpd|proftpd|pureftpd|filezilla)/i },
  { name: "FTP", pattern: /^220[\s-]/i },
  // SMTP
  { name: "SMTP", pattern: /^220[\s-].*(?:smtp|postfix|sendmail|exim|exchange)/i },
  { name: "SMTP", pattern: /^220[\s-].*ESMTP/i },
  // POP3
  { name: "POP3", pattern: /^\+OK.*(?:pop|dovecot|courier|cyrus)/i },
  { name: "POP3", pattern: /^\+OK/i },
  // IMAP
  { name: "IMAP", pattern: /^\* OK.*(?:imap|dovecot|courier|cyrus)/i },
  // HTTP
  { name: "HTTP", pattern: /^HTTP\/(\d+\.\d+)\s+\d+/i, versionGroup: 1 },
  // MySQL
  { name: "MySQL", pattern: /mysql/i },
  { name: "MySQL", pattern: /^.\0\0\0\n([\d.]+)/i, versionGroup: 1 },
  // PostgreSQL
  { name: "PostgreSQL", pattern: /postgres/i },
  // Redis
  { name: "Redis", pattern: /^-ERR.*redis/i },
  { name: "Redis", pattern: /^\$\d+\r\n# Server/i },
  { name: "Redis", pattern: /^-DENIED/i },
  // MongoDB
  { name: "MongoDB", pattern: /mongodb/i },
  { name: "MongoDB", pattern: /^.*ismaster/i },
  // RDP
  { name: "RDP", pattern: /^\x03\x00/i },
  // VNC
  { name: "VNC", pattern: /^RFB (\d+\.\d+)/i, versionGroup: 1 },
  // DNS
  { name: "DNS", pattern: /^\0.{4,}/i },
  // LDAP
  { name: "LDAP", pattern: /ldap/i },
  // Elasticsearch
  { name: "Elasticsearch", pattern: /elasticsearch/i },
  { name: "Elasticsearch", pattern: /"cluster_name"/i },
  // Apache/Nginx/IIS banners
  { name: "Apache", pattern: /Apache\/([\d.]+)/i, versionGroup: 1 },
  { name: "Nginx", pattern: /nginx\/([\d.]+)/i, versionGroup: 1 },
  { name: "IIS", pattern: /Microsoft-IIS\/([\d.]+)/i, versionGroup: 1 },
  // OpenSSL in banner
  { name: "OpenSSL", pattern: /OpenSSL\/([\d.a-z]+)/i, versionGroup: 1 },
  // Telnet
  { name: "Telnet", pattern: /telnet/i },
  { name: "Telnet", pattern: /^\xff[\xfb\xfd\xfe]/i },
  // Docker
  { name: "Docker API", pattern: /docker/i },
  // Memcached
  { name: "Memcached", pattern: /^ERROR\r?\n/i },
  // RabbitMQ
  { name: "RabbitMQ", pattern: /AMQP/i },
];

// ---------------------------------------------------------------------------
// Well-known port-to-service mapping (used when banner grab fails)
// ---------------------------------------------------------------------------
const WELL_KNOWN_SERVICES: Record<number, string> = {
  20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
  43: "WHOIS", 53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
  80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCBind",
  119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
  138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
  161: "SNMP", 162: "SNMP-Trap", 179: "BGP", 194: "IRC",
  389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos",
  465: "SMTPS", 500: "IKE/IPsec", 514: "Syslog", 515: "LPD",
  520: "RIP", 521: "RIPng", 523: "IBM-DB2", 524: "NCP",
  530: "RPC", 543: "Klogin", 544: "Kshell", 548: "AFP",
  554: "RTSP", 563: "NNTPS", 587: "Submission", 593: "MS-RPC-HTTP",
  631: "IPP/CUPS", 636: "LDAPS", 873: "Rsync", 902: "VMware",
  990: "FTPS", 993: "IMAPS", 995: "POP3S",
  1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1434: "MSSQL-UDP",
  1521: "Oracle-DB", 1723: "PPTP", 1883: "MQTT",
  2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
  2181: "ZooKeeper", 2222: "SSH-Alt",
  3000: "Dev-Server", 3128: "Squid-Proxy", 3268: "LDAP-GC",
  3269: "LDAP-GC-SSL", 3306: "MySQL", 3389: "RDP",
  3690: "SVN", 4443: "HTTPS-Alt", 4444: "Metasploit",
  4567: "Dev-Server", 4848: "GlassFish",
  5000: "Docker-Registry", 5432: "PostgreSQL",
  5060: "SIP", 5061: "SIP-TLS", 5222: "XMPP",
  5269: "XMPP-S2S",
  5555: "ADB", 5672: "AMQP", 5900: "VNC", 5984: "CouchDB",
  6379: "Redis", 6443: "Kubernetes-API",
  6666: "IRC", 6667: "IRC", 6697: "IRC-SSL",
  7001: "WebLogic", 7070: "RealServer", 7443: "HTTPS-Alt",
  8000: "HTTP-Alt", 8008: "HTTP-Alt", 8009: "AJP",
  8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8082: "HTTP-Alt",
  8083: "HTTP-Alt", 8084: "HTTP-Alt", 8085: "HTTP-Alt",
  8086: "InfluxDB", 8088: "HTTP-Alt", 8089: "Splunk",
  8090: "HTTP-Alt", 8181: "HTTP-Alt", 8200: "Vault",
  8333: "Bitcoin", 8443: "HTTPS-Alt", 8500: "Consul",
  8787: "RStudio", 8834: "Nessus", 8888: "HTTP-Alt",
  9000: "SonarQube", 9001: "Tor-ORPort", 9042: "Cassandra",
  9090: "Prometheus", 9092: "Kafka", 9100: "JetDirect",
  9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
  9418: "Git", 9443: "HTTPS-Alt", 9999: "HTTP-Alt",
  10000: "Webmin", 10250: "Kubelet", 10443: "HTTPS-Alt",
  11211: "Memcached", 15672: "RabbitMQ-Mgmt",
  27017: "MongoDB", 27018: "MongoDB-Shard", 27019: "MongoDB-Config",
  28017: "MongoDB-HTTP",
  50000: "SAP", 50070: "HDFS-NameNode",
};

// ---------------------------------------------------------------------------
// PortScanner
// ---------------------------------------------------------------------------

export class PortScanner implements ScanModule {
  readonly name = "recon:port-scan";

  private connectTimeoutMs = 3000;
  private bannerTimeoutMs = 5000;
  private maxConcurrency = 50;
  private ports: number[] = [];

  async init(
    _target: string,
    options: Record<string, unknown>,
  ): Promise<void> {
    if (typeof options.requestTimeoutMs === "number") {
      this.connectTimeoutMs = Math.min(options.requestTimeoutMs, 10000);
      this.bannerTimeoutMs = Math.min(options.requestTimeoutMs, 15000);
    }
    if (typeof options.maxConcurrency === "number") {
      this.maxConcurrency = Math.min(options.maxConcurrency, 200);
    }

    // Allow custom port ranges via module options
    if (Array.isArray(options.ports)) {
      this.ports = (options.ports as number[]).filter(
        (p) => typeof p === "number" && p >= 1 && p <= 65535,
      );
    } else if (typeof options.portRange === "string") {
      this.ports = this.parsePortRange(options.portRange as string);
    } else if (typeof options.topPorts === "number") {
      const count = Math.min(options.topPorts as number, TOP_1000_PORTS.length);
      this.ports = TOP_1000_PORTS.slice(0, count);
    } else {
      // Default to top 1000 ports
      this.ports = [...TOP_1000_PORTS];
    }

    log.info(
      { portCount: this.ports.length, concurrency: this.maxConcurrency },
      "PortScanner initialized",
    );
  }

  async *execute(
    target: string,
    _options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const host = this.extractHost(target);
    log.info({ host, portCount: this.ports.length }, "Starting port scan");

    // Scan in batches for concurrency control
    for (let i = 0; i < this.ports.length; i += this.maxConcurrency) {
      const batch = this.ports.slice(i, i + this.maxConcurrency);
      const results = await Promise.allSettled(
        batch.map((port) => this.scanPort(host, port)),
      );

      for (const result of results) {
        if (result.status === "fulfilled" && result.value !== null) {
          const { port, banner, service, version } = result.value;
          yield this.createFinding(host, port, banner, service, version);
        }
      }
    }

    log.info({ host }, "Port scan complete");
  }

  async cleanup(): Promise<void> {
    log.info("PortScanner cleanup complete");
  }

  // -------------------------------------------------------------------------
  // Core Scanning
  // -------------------------------------------------------------------------

  /**
   * Attempt a TCP connect to `host:port`. If the port is open, try to grab
   * a banner. Returns null if the port is closed/filtered.
   */
  private async scanPort(
    host: string,
    port: number,
  ): Promise<{
    port: number;
    banner: string;
    service: string;
    version: string;
  } | null> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let banner = "";
      let resolved = false;

      const finish = (
        result: {
          port: number;
          banner: string;
          service: string;
          version: string;
        } | null,
      ) => {
        if (resolved) return;
        resolved = true;
        socket.removeAllListeners();
        socket.destroy();
        resolve(result);
      };

      // Connection timeout
      socket.setTimeout(this.connectTimeoutMs);

      socket.on("timeout", () => {
        finish(null);
      });

      socket.on("error", () => {
        finish(null);
      });

      socket.on("connect", () => {
        // Port is open. Try to read a banner.
        socket.setTimeout(this.bannerTimeoutMs);

        // Some services require an initial probe to get a banner
        // Send a minimal probe for HTTP-like ports
        const httpPorts = new Set([
          80, 443, 8000, 8008, 8080, 8081, 8082, 8083, 8084, 8085,
          8086, 8088, 8089, 8090, 8181, 8443, 8888, 9000, 9090, 9200,
          9443, 3000, 3001, 4443, 5000, 7443,
        ]);

        if (httpPorts.has(port)) {
          socket.write(
            `HEAD / HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: VulnHunter/1.0\r\n\r\n`,
          );
        } else {
          // Generic probe: send a newline to elicit a banner
          socket.write("\r\n");
        }
      });

      socket.on("data", (data: Buffer) => {
        banner += data.toString("utf8", 0, Math.min(data.length, 4096));

        // We have some data, process it
        if (banner.length > 0) {
          const { service, version } = this.identifyService(port, banner);
          finish({ port, banner: banner.slice(0, 1024), service, version });
        }
      });

      // If we connected but got no data before timeout, still report the open port
      socket.on("timeout", () => {
        if (!resolved && socket.connecting === false) {
          // Port was open but no banner
          const service =
            WELL_KNOWN_SERVICES[port] ?? "unknown";
          finish({ port, banner: "", service, version: "" });
        } else {
          finish(null);
        }
      });

      socket.on("end", () => {
        if (!resolved) {
          const { service, version } = this.identifyService(port, banner);
          finish({
            port,
            banner: banner.slice(0, 1024),
            service,
            version,
          });
        }
      });

      try {
        socket.connect(port, host);
      } catch {
        finish(null);
      }
    });
  }

  // -------------------------------------------------------------------------
  // Service Identification
  // -------------------------------------------------------------------------

  /**
   * Identify the service and version from the captured banner text.
   * Falls back to the well-known port mapping if no signature matches.
   */
  private identifyService(
    port: number,
    banner: string,
  ): { service: string; version: string } {
    if (banner.length > 0) {
      for (const sig of SERVICE_SIGNATURES) {
        const match = banner.match(sig.pattern);
        if (match) {
          const version =
            sig.versionGroup !== undefined && match[sig.versionGroup]
              ? match[sig.versionGroup]
              : "";
          return { service: sig.name, version };
        }
      }
    }

    // Fall back to well-known port mapping
    return {
      service: WELL_KNOWN_SERVICES[port] ?? "unknown",
      version: "",
    };
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /**
   * Extract host (IP or hostname) from a target string.
   */
  private extractHost(target: string): string {
    let host = target;

    if (host.includes("://")) {
      try {
        const parsed = new URL(host);
        host = parsed.hostname;
      } catch {
        host = host.replace(/^[a-z]+:\/\//i, "");
      }
    }

    // Strip port
    host = host.split(":")[0];
    // Strip path
    host = host.split("/")[0];

    return host;
  }

  /**
   * Parse a port range string like "1-1024" or "80,443,8080-8090".
   */
  private parsePortRange(rangeStr: string): number[] {
    const ports: number[] = [];
    const parts = rangeStr.split(",").map((s) => s.trim());

    for (const part of parts) {
      if (part.includes("-")) {
        const [startStr, endStr] = part.split("-");
        const start = parseInt(startStr, 10);
        const end = parseInt(endStr, 10);
        if (!isNaN(start) && !isNaN(end) && start >= 1 && end <= 65535) {
          for (let p = start; p <= end; p++) {
            ports.push(p);
          }
        }
      } else {
        const p = parseInt(part, 10);
        if (!isNaN(p) && p >= 1 && p <= 65535) {
          ports.push(p);
        }
      }
    }

    return ports;
  }

  /**
   * Convert a port scan result into a Finding.
   */
  private createFinding(
    host: string,
    port: number,
    banner: string,
    service: string,
    version: string,
  ): Finding {
    const now = new Date().toISOString();
    const serviceDisplay = version
      ? `${service}/${version}`
      : service;

    const vulnerability: Vulnerability = {
      id: uuid(),
      title: `Open port ${port}/${serviceDisplay} on ${host}`,
      description:
        `TCP port ${port} is open on ${host} and appears to be running ${serviceDisplay}. ` +
        (banner
          ? `The following banner was captured: "${banner.slice(0, 200).replace(/[\r\n]+/g, " ")}".`
          : "No banner was captured.") +
        ` Open ports expose services to the network and should be reviewed for security.`,
      severity: this.assessSeverity(port, service),
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore: 0.0,
      target: host,
      endpoint: `${host}:${port}`,
      evidence: {
        description: `TCP connect scan confirmed port ${port} is open`,
        extra: {
          port,
          protocol: "tcp",
          service,
          version,
          banner: banner.slice(0, 512),
        },
      },
      remediation:
        `Review whether port ${port} (${service}) needs to be publicly accessible. ` +
        `If not required, close the port or restrict access via firewall rules. ` +
        `Ensure the service is up-to-date and securely configured.`,
      references: [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver",
      ],
      confirmed: true,
      falsePositive: false,
      discoveredAt: now,
    };

    return {
      vulnerability,
      module: this.name,
      confidence: 95,
      timestamp: now,
      rawData: {
        host,
        port,
        banner: banner.slice(0, 1024),
        service,
        version,
      },
    };
  }

  /**
   * Assess the severity of an open port finding. Database, admin, and
   * development ports get higher severity; standard web ports stay info.
   */
  private assessSeverity(port: number, service: string): Severity {
    // High-risk services that should rarely be publicly exposed
    const highRiskPorts = new Set([
      22, 23, 135, 139, 445, 1433, 1434, 1521, 3306, 3389,
      5432, 5900, 6379, 9200, 11211, 27017, 27018, 27019,
    ]);

    const mediumRiskPorts = new Set([
      21, 25, 53, 110, 143, 161, 389, 514, 636,
      873, 993, 995, 2049, 5060, 5061,
    ]);

    const highRiskServices = new Set([
      "MySQL", "PostgreSQL", "MSSQL", "Oracle-DB", "MongoDB",
      "Redis", "Memcached", "Elasticsearch", "CouchDB",
      "RDP", "VNC", "Telnet", "SSH",
    ]);

    if (highRiskPorts.has(port) || highRiskServices.has(service)) {
      return Severity.Medium;
    }

    if (mediumRiskPorts.has(port)) {
      return Severity.Low;
    }

    return Severity.Info;
  }
}
