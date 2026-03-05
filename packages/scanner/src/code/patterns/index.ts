// =============================================================================
// @vulnhunter/scanner - Vulnerability Pattern Database
// =============================================================================
// Comprehensive regex-based vulnerability patterns for static analysis across
// multiple programming languages. Each pattern includes CWE mapping, severity
// rating, and actionable remediation guidance.
// =============================================================================

/**
 * A single vulnerability detection pattern used by the SAST engine.
 */
export interface VulnerabilityPattern {
  /** Unique identifier for this pattern, e.g. "js-eval-injection" */
  id: string;
  /** Human-readable name displayed in findings */
  name: string;
  /** Target language (or "any" for cross-language patterns) */
  language: string;
  /** Regular expression to match vulnerable code */
  pattern: RegExp;
  /** Severity rating for findings produced by this pattern */
  severity: "critical" | "high" | "medium" | "low" | "info";
  /** Vulnerability category for classification */
  category: string;
  /** CWE identifier, e.g. "CWE-78" */
  cweId: string;
  /** CVSS v3.1 base score estimate */
  cvssScore: number;
  /** Detailed description of what this pattern detects */
  description: string;
  /** Recommended fix or mitigation */
  remediation: string;
  /** File extensions this pattern applies to (empty = all files of that language) */
  fileExtensions?: string[];
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript Patterns
// ---------------------------------------------------------------------------

export const jsPatterns: VulnerabilityPattern[] = [
  {
    id: "js-eval-injection",
    name: "eval() Code Injection",
    language: "javascript",
    pattern: /\beval\s*\(/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-95",
    cvssScore: 9.8,
    description:
      "Usage of eval() can allow arbitrary code execution if user-controlled data reaches the eval argument. This is one of the most dangerous JavaScript anti-patterns.",
    remediation:
      "Replace eval() with JSON.parse() for data parsing, Function constructor for controlled scenarios, or use a sandboxed interpreter. Never pass user input to eval().",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-function-constructor",
    name: "Function Constructor Code Injection",
    language: "javascript",
    pattern: /new\s+Function\s*\(/g,
    severity: "high",
    category: "rce",
    cweId: "CWE-95",
    cvssScore: 8.1,
    description:
      "The Function constructor is functionally equivalent to eval() and can execute arbitrary code strings. User-controlled input reaching this constructor enables remote code execution.",
    remediation:
      "Avoid dynamic code generation. Use static function definitions, lookup tables, or strategy patterns instead.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-innerhtml-xss",
    name: "innerHTML XSS Sink",
    language: "javascript",
    pattern: /\.innerHTML\s*=\s*/g,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    cvssScore: 6.1,
    description:
      "Direct assignment to innerHTML inserts raw HTML into the DOM without sanitization, enabling cross-site scripting attacks if user-controlled data is included.",
    remediation:
      "Use textContent for text-only assignments, or use a sanitization library like DOMPurify before assigning to innerHTML. Consider using a framework's built-in escaping.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-outerhtml-xss",
    name: "outerHTML XSS Sink",
    language: "javascript",
    pattern: /\.outerHTML\s*=\s*/g,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    cvssScore: 6.1,
    description:
      "Direct assignment to outerHTML replaces the element and its content with raw HTML, enabling XSS if user-controlled data is included.",
    remediation:
      "Use textContent or sanitize input with DOMPurify before assigning to outerHTML.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-document-write-xss",
    name: "document.write() XSS Sink",
    language: "javascript",
    pattern: /document\.write(?:ln)?\s*\(/g,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    cvssScore: 6.1,
    description:
      "document.write() injects raw HTML into the document stream. If user-controlled data reaches this call, attackers can inject arbitrary scripts.",
    remediation:
      "Use DOM manipulation methods (createElement, appendChild) instead of document.write(). Modern frameworks handle this automatically.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-dangerously-set-innerhtml",
    name: "React dangerouslySetInnerHTML XSS",
    language: "javascript",
    pattern: /dangerouslySetInnerHTML\s*=\s*\{/g,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    cvssScore: 6.1,
    description:
      "React's dangerouslySetInnerHTML bypasses the virtual DOM's built-in XSS protection. If user input flows into the __html property, cross-site scripting is possible.",
    remediation:
      "Avoid dangerouslySetInnerHTML. If you must render HTML, sanitize it with DOMPurify before passing it. Consider using a markdown renderer or safe HTML component.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx"],
  },
  {
    id: "js-exec-command-injection",
    name: "child_process Command Injection",
    language: "javascript",
    pattern: /(?:child_process|exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-78",
    cvssScore: 9.8,
    description:
      "Calling child_process methods with user-controlled input can lead to operating system command injection, allowing an attacker to execute arbitrary system commands.",
    remediation:
      "Use execFile/execFileSync with explicit argument arrays instead of exec/execSync with string concatenation. Validate and sanitize all input passed to command execution functions.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-sql-concat",
    name: "SQL String Concatenation",
    language: "javascript",
    pattern: /(?:query|execute|raw|prepare)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/g,
    severity: "critical",
    category: "sqli",
    cweId: "CWE-89",
    cvssScore: 9.8,
    description:
      "Building SQL queries through string concatenation or template literals with embedded variables creates SQL injection vulnerabilities when user input is included.",
    remediation:
      "Use parameterized queries (prepared statements) with placeholder values. All database libraries (pg, mysql2, knex, prisma) support parameterized queries natively.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-path-traversal",
    name: "Path Traversal via User Input",
    language: "javascript",
    pattern: /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|access|accessSync|stat|statSync|unlink|unlinkSync|readdir|readdirSync)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|args\.|input)/g,
    severity: "high",
    category: "lfi",
    cweId: "CWE-22",
    cvssScore: 7.5,
    description:
      "File system operations using unsanitized user input (from request parameters, query strings, or body) can allow attackers to read or write arbitrary files via path traversal sequences.",
    remediation:
      "Use path.resolve() with a base directory and verify the resolved path starts with the expected prefix. Use path.normalize() and reject paths containing '..' components.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-unsafe-deserialization",
    name: "Unsafe Deserialization",
    language: "javascript",
    pattern: /(?:node-serialize|serialize-javascript|js-yaml\.load\s*\(|unserialize\s*\(|deserialize\s*\()/g,
    severity: "critical",
    category: "deserialization",
    cweId: "CWE-502",
    cvssScore: 9.8,
    description:
      "Deserializing untrusted data can lead to remote code execution. Libraries like node-serialize and unsafe YAML loading modes are particularly dangerous.",
    remediation:
      "Use JSON.parse() for data interchange. If YAML is required, use yaml.safeLoad() or js-yaml with schema: FAILSAFE_SCHEMA. Never deserialize untrusted data with generic deserializers.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-prototype-pollution",
    name: "Prototype Pollution",
    language: "javascript",
    pattern: /(?:__proto__|constructor\s*\[\s*['"]prototype['"]|Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:req\.|request\.|body\.|params\.|query\.|input))/g,
    severity: "high",
    category: "rce",
    cweId: "CWE-1321",
    cvssScore: 7.3,
    description:
      "Prototype pollution occurs when an attacker can modify the prototype of base objects (Object.prototype), potentially leading to property injection, denial of service, or remote code execution.",
    remediation:
      "Use Object.create(null) for dictionary objects. Validate and sanitize object keys before merging. Use Map instead of plain objects for user-controlled keys. Consider using lodash's _.merge with a custom handler.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-insecure-crypto",
    name: "Insecure Cryptographic Algorithm",
    language: "javascript",
    pattern: /createHash\s*\(\s*['"](?:md5|sha1|md4|md2|ripemd160)['"]\s*\)/g,
    severity: "medium",
    category: "cryptographic",
    cweId: "CWE-327",
    cvssScore: 5.3,
    description:
      "Using weak or deprecated hash algorithms (MD5, SHA-1, MD4, MD2) for security-sensitive operations (password hashing, HMAC, digital signatures) is insecure due to known collision and preimage attacks.",
    remediation:
      "Use SHA-256 or SHA-3 for general hashing. For password hashing, use bcrypt, scrypt, or Argon2. Never use MD5 or SHA-1 for security purposes.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-insecure-random",
    name: "Insecure Random Number Generation",
    language: "javascript",
    pattern: /Math\.random\s*\(\s*\)/g,
    severity: "medium",
    category: "cryptographic",
    cweId: "CWE-338",
    cvssScore: 5.3,
    description:
      "Math.random() uses a PRNG that is not cryptographically secure. Using it for tokens, session IDs, passwords, or any security-sensitive value is vulnerable to prediction attacks.",
    remediation:
      "Use crypto.randomBytes() or crypto.randomUUID() in Node.js. In the browser, use crypto.getRandomValues(). For token generation, use dedicated libraries like nanoid or uuid.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-hardcoded-secret",
    name: "Hardcoded Secret in Source Code",
    language: "javascript",
    pattern: /(?:const|let|var)\s+\w*(?:secret|password|passwd|api_?key|apikey|token|auth|credential|private_?key)\w*\s*=\s*['"][^'"]{8,}['"]/gi,
    severity: "high",
    category: "information_disclosure",
    cweId: "CWE-798",
    cvssScore: 7.5,
    description:
      "Hardcoded secrets (API keys, passwords, tokens) in source code can be extracted by anyone with access to the codebase, including through version control history.",
    remediation:
      "Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler). Never commit secrets to version control.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-cors-wildcard",
    name: "Permissive CORS Configuration",
    language: "javascript",
    pattern: /(?:Access-Control-Allow-Origin|cors)\s*[:(]\s*['"][*]['"]/g,
    severity: "medium",
    category: "cors",
    cweId: "CWE-942",
    cvssScore: 5.3,
    description:
      "Setting Access-Control-Allow-Origin to '*' allows any website to make cross-origin requests to the application, potentially exposing sensitive data.",
    remediation:
      "Specify an explicit allowlist of trusted origins. If dynamic origins are needed, validate the Origin header against a whitelist before reflecting it.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-jwt-no-verify",
    name: "JWT Without Verification",
    language: "javascript",
    pattern: /jwt\.decode\s*\(/g,
    severity: "high",
    category: "auth_bypass",
    cweId: "CWE-345",
    cvssScore: 7.5,
    description:
      "Using jwt.decode() instead of jwt.verify() processes the JWT payload without validating the signature, allowing attackers to forge tokens with arbitrary claims.",
    remediation:
      "Always use jwt.verify() with a strong secret or public key. Never trust decoded JWT payloads without signature verification.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-nosql-injection",
    name: "NoSQL Injection",
    language: "javascript",
    pattern: /(?:find|findOne|findMany|aggregate|update|delete|remove)\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.)/g,
    severity: "critical",
    category: "sqli",
    cweId: "CWE-943",
    cvssScore: 9.1,
    description:
      "Passing unsanitized user input directly to MongoDB/NoSQL query methods can allow attackers to modify query logic using operators like $gt, $ne, $regex.",
    remediation:
      "Validate and sanitize all user inputs before using in queries. Use mongoose schema validation, express-mongo-sanitize middleware, or explicitly cast types.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-ssrf-fetch",
    name: "Server-Side Request Forgery via Fetch",
    language: "javascript",
    pattern: /(?:fetch|got|axios|request|http\.get|https\.get)\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.|input|url|target|host|endpoint)/g,
    severity: "high",
    category: "ssrf",
    cweId: "CWE-918",
    cvssScore: 7.5,
    description:
      "Making HTTP requests to URLs derived from user input without validation can allow attackers to reach internal services, cloud metadata endpoints, or other restricted resources.",
    remediation:
      "Validate and sanitize all user-provided URLs. Implement an allowlist of permitted domains/IPs. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x) and localhost.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-open-redirect",
    name: "Open Redirect",
    language: "javascript",
    pattern: /(?:redirect|location\.href|location\.assign|location\.replace|window\.open)\s*[=(]\s*(?:req\.|request\.|body\.|params\.|query\.|input)/g,
    severity: "medium",
    category: "open_redirect",
    cweId: "CWE-601",
    cvssScore: 4.7,
    description:
      "Using user-controlled input in redirect destinations without validation allows attackers to redirect users to malicious websites for phishing or credential theft.",
    remediation:
      "Validate redirect URLs against an allowlist of permitted domains. Use relative paths for internal redirects. Never redirect to user-supplied absolute URLs without validation.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-regex-dos",
    name: "Regular Expression Denial of Service (ReDoS)",
    language: "javascript",
    pattern: /new\s+RegExp\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.|input)/g,
    severity: "medium",
    category: "rce",
    cweId: "CWE-1333",
    cvssScore: 5.3,
    description:
      "Constructing regular expressions from user input can lead to catastrophic backtracking (ReDoS), causing denial of service by exhausting CPU resources.",
    remediation:
      "Never construct RegExp from user input. If dynamic patterns are required, use a regex timeout (RE2 library) or validate that the pattern is safe before compilation.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-unsafe-setTimeout",
    name: "setTimeout/setInterval with String Argument",
    language: "javascript",
    pattern: /(?:setTimeout|setInterval)\s*\(\s*['"`]/g,
    severity: "medium",
    category: "rce",
    cweId: "CWE-95",
    cvssScore: 6.1,
    description:
      "Passing a string argument to setTimeout or setInterval causes it to be evaluated as code (similar to eval). If user input can influence this string, code injection is possible.",
    remediation:
      "Always pass a function reference to setTimeout/setInterval, never a string. Use arrow functions or named functions.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    id: "js-missing-helmet",
    name: "Express App Without Helmet Security Headers",
    language: "javascript",
    pattern: /app\s*=\s*express\s*\(\s*\)/g,
    severity: "low",
    category: "header_misconfig",
    cweId: "CWE-693",
    cvssScore: 3.7,
    description:
      "Express applications without the helmet middleware lack important security headers (X-Content-Type-Options, X-Frame-Options, CSP, HSTS, etc.).",
    remediation:
      "Install and use the helmet middleware: app.use(helmet()). This sets secure defaults for HTTP response headers.",
    fileExtensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
];

// ---------------------------------------------------------------------------
// Python Patterns
// ---------------------------------------------------------------------------

export const pythonPatterns: VulnerabilityPattern[] = [
  {
    id: "py-eval-injection",
    name: "eval() Code Injection",
    language: "python",
    pattern: /\beval\s*\(/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-95",
    cvssScore: 9.8,
    description:
      "Python's eval() executes arbitrary expressions. If user input reaches eval, attackers can execute arbitrary Python code on the server.",
    remediation:
      "Use ast.literal_eval() for safe evaluation of literals. For mathematical expressions, use a safe parser library. Never pass user input to eval().",
    fileExtensions: [".py"],
  },
  {
    id: "py-exec-injection",
    name: "exec() Code Injection",
    language: "python",
    pattern: /\bexec\s*\(/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-95",
    cvssScore: 9.8,
    description:
      "Python's exec() executes arbitrary Python statements. User-controlled input reaching exec enables full remote code execution.",
    remediation:
      "Eliminate exec() usage entirely. Use structured data processing, lookup tables, or plugin architectures instead of dynamic code execution.",
    fileExtensions: [".py"],
  },
  {
    id: "py-os-system",
    name: "os.system() Command Injection",
    language: "python",
    pattern: /os\.(?:system|popen)\s*\(/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-78",
    cvssScore: 9.8,
    description:
      "os.system() and os.popen() execute commands through the shell, making them vulnerable to command injection when user input is included.",
    remediation:
      "Use subprocess.run() with shell=False and pass arguments as a list. Use shlex.quote() if shell execution is absolutely required.",
    fileExtensions: [".py"],
  },
  {
    id: "py-subprocess-shell",
    name: "subprocess with shell=True",
    language: "python",
    pattern: /subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-78",
    cvssScore: 9.8,
    description:
      "Using subprocess with shell=True interprets the command through the system shell, enabling command injection via shell metacharacters in user input.",
    remediation:
      "Use shell=False (the default) and pass the command as a list of arguments: subprocess.run(['cmd', 'arg1', 'arg2']).",
    fileExtensions: [".py"],
  },
  {
    id: "py-sql-concat",
    name: "SQL String Concatenation",
    language: "python",
    pattern: /(?:execute|executemany|raw)\s*\(\s*(?:f['"]|['"][^'"]*['"]\s*%|['"][^'"]*['"]\s*\.format\s*\(|['"][^'"]*['"]\s*\+)/g,
    severity: "critical",
    category: "sqli",
    cweId: "CWE-89",
    cvssScore: 9.8,
    description:
      "Building SQL queries through string formatting (f-strings, % formatting, .format(), concatenation) creates SQL injection vulnerabilities.",
    remediation:
      "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)). Use an ORM like SQLAlchemy or Django ORM.",
    fileExtensions: [".py"],
  },
  {
    id: "py-pickle-deserialization",
    name: "Unsafe Pickle Deserialization",
    language: "python",
    pattern: /pickle\.(?:loads?|Unpickler)\s*\(/g,
    severity: "critical",
    category: "deserialization",
    cweId: "CWE-502",
    cvssScore: 9.8,
    description:
      "Pickle deserialization of untrusted data can execute arbitrary code via __reduce__ methods. This is a well-known Python RCE vector.",
    remediation:
      "Never unpickle data from untrusted sources. Use JSON, MessagePack, or Protocol Buffers for data serialization. If pickle is required, use hmac signing to verify data integrity.",
    fileExtensions: [".py"],
  },
  {
    id: "py-yaml-load",
    name: "Unsafe YAML Loading",
    language: "python",
    pattern: /yaml\.load\s*\([^)]*(?!\bLoader\s*=\s*(?:Safe|Base)Loader\b)/g,
    severity: "critical",
    category: "deserialization",
    cweId: "CWE-502",
    cvssScore: 9.8,
    description:
      "yaml.load() without specifying Loader=SafeLoader can execute arbitrary Python objects, leading to remote code execution.",
    remediation:
      "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader). Never use yaml.load() with FullLoader or UnsafeLoader on untrusted data.",
    fileExtensions: [".py"],
  },
  {
    id: "py-flask-debug",
    name: "Flask Debug Mode Enabled",
    language: "python",
    pattern: /app\.run\s*\([^)]*debug\s*=\s*True/g,
    severity: "high",
    category: "information_disclosure",
    cweId: "CWE-215",
    cvssScore: 7.5,
    description:
      "Flask debug mode exposes an interactive debugger (Werkzeug) that allows arbitrary code execution from the browser. It also leaks detailed error information.",
    remediation:
      "Never enable debug mode in production. Use environment variables: app.run(debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true').",
    fileExtensions: [".py"],
  },
  {
    id: "py-hardcoded-secret",
    name: "Hardcoded Secret in Python Code",
    language: "python",
    pattern: /(?:SECRET_KEY|PASSWORD|API_KEY|PRIVATE_KEY|TOKEN|AUTH_TOKEN|DATABASE_URL|DB_PASSWORD)\s*=\s*['"][^'"]{8,}['"]/gi,
    severity: "high",
    category: "information_disclosure",
    cweId: "CWE-798",
    cvssScore: 7.5,
    description:
      "Hardcoded secrets in Python source code can be extracted by anyone with access to the repository or deployment artifacts.",
    remediation:
      "Use environment variables (os.getenv()), python-decouple, or a secrets manager. Store secrets in .env files excluded from version control.",
    fileExtensions: [".py"],
  },
  {
    id: "py-ssrf",
    name: "Server-Side Request Forgery",
    language: "python",
    pattern: /(?:requests\.(?:get|post|put|delete|patch|head|options)|urllib\.request\.urlopen|httpx\.(?:get|post|AsyncClient))\s*\(\s*(?:request\.|args\.|form\.|data\[|params\[|input)/g,
    severity: "high",
    category: "ssrf",
    cweId: "CWE-918",
    cvssScore: 7.5,
    description:
      "Making HTTP requests to user-controlled URLs can allow attackers to probe internal networks, access cloud metadata, or interact with internal services.",
    remediation:
      "Validate URLs against an allowlist. Block private IP ranges. Use a URL validation library. Consider using a proxy with network policies.",
    fileExtensions: [".py"],
  },
  {
    id: "py-path-traversal",
    name: "Path Traversal",
    language: "python",
    pattern: /open\s*\(\s*(?:request\.|args\.|form\.|data\[|params\[|f['"]|os\.path\.join\s*\([^)]*(?:request|args|form|data|params))/g,
    severity: "high",
    category: "lfi",
    cweId: "CWE-22",
    cvssScore: 7.5,
    description:
      "Opening files with paths derived from user input without proper validation allows attackers to read or write arbitrary files using path traversal sequences (../).",
    remediation:
      "Use os.path.realpath() to resolve symlinks, then verify the resolved path starts with the expected base directory. Use pathlib.Path.resolve() for modern Python.",
    fileExtensions: [".py"],
  },
  {
    id: "py-insecure-hash",
    name: "Insecure Hash Algorithm",
    language: "python",
    pattern: /hashlib\.(?:md5|sha1)\s*\(/g,
    severity: "medium",
    category: "cryptographic",
    cweId: "CWE-327",
    cvssScore: 5.3,
    description:
      "MD5 and SHA-1 are cryptographically broken hash algorithms. Using them for security purposes (password hashing, integrity verification) is insecure.",
    remediation:
      "Use hashlib.sha256() or hashlib.sha3_256() for general hashing. For passwords, use bcrypt, argon2-cffi, or hashlib.scrypt().",
    fileExtensions: [".py"],
  },
  {
    id: "py-insecure-random",
    name: "Insecure Random for Security Context",
    language: "python",
    pattern: /\brandom\.(?:random|randint|choice|randrange|sample)\s*\(/g,
    severity: "medium",
    category: "cryptographic",
    cweId: "CWE-338",
    cvssScore: 5.3,
    description:
      "Python's random module uses a Mersenne Twister PRNG that is not cryptographically secure. Using it for tokens, sessions, or security-sensitive values is predictable.",
    remediation:
      "Use secrets.token_hex(), secrets.token_urlsafe(), or secrets.SystemRandom() for security-sensitive random values.",
    fileExtensions: [".py"],
  },
  {
    id: "py-jinja2-autoescape",
    name: "Jinja2 Template Without Autoescaping",
    language: "python",
    pattern: /Environment\s*\([^)]*autoescape\s*=\s*False/g,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    cvssScore: 6.1,
    description:
      "Disabling Jinja2's autoescape feature allows template injection and cross-site scripting when user input is rendered in templates.",
    remediation:
      "Enable autoescape: Environment(autoescape=True) or use select_autoescape(['html', 'xml']). Never disable autoescape when rendering user content.",
    fileExtensions: [".py"],
  },
  {
    id: "py-django-raw-sql",
    name: "Django Raw SQL Query",
    language: "python",
    pattern: /(?:\.raw|\.extra|connection\.cursor)\s*\(/g,
    severity: "high",
    category: "sqli",
    cweId: "CWE-89",
    cvssScore: 8.6,
    description:
      "Django's .raw(), .extra(), and raw cursor operations bypass the ORM's built-in SQL injection protections. User input in these queries can lead to SQL injection.",
    remediation:
      "Use Django's ORM query methods (filter, exclude, annotate) instead of raw SQL. If raw SQL is necessary, use parameterized queries with params argument.",
    fileExtensions: [".py"],
  },
  {
    id: "py-mass-assignment",
    name: "Mass Assignment / Over-Posting",
    language: "python",
    pattern: /\*\*request\.(?:data|json|form|POST|GET)\b/g,
    severity: "high",
    category: "auth_bypass",
    cweId: "CWE-915",
    cvssScore: 7.5,
    description:
      "Unpacking request data directly into model constructors or update calls allows attackers to set unintended fields (e.g., is_admin, role, balance).",
    remediation:
      "Explicitly whitelist allowed fields. Use serializers with declared fields (DRF), Pydantic models, or form validation to control accepted input.",
    fileExtensions: [".py"],
  },
  {
    id: "py-tempfile-insecure",
    name: "Insecure Temporary File Creation",
    language: "python",
    pattern: /tempfile\.mk(?:s?temp)\s*\(/g,
    severity: "low",
    category: "lfi",
    cweId: "CWE-377",
    cvssScore: 3.3,
    description:
      "tempfile.mktemp() creates a name but not the file, creating a race condition (TOCTOU) that attackers can exploit via symlink attacks.",
    remediation:
      "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() which create the file atomically with secure permissions.",
    fileExtensions: [".py"],
  },
  {
    id: "py-assert-security",
    name: "Assert Used for Security Check",
    language: "python",
    pattern: /assert\s+(?:request|user|session|token|auth|permission|role)\b/g,
    severity: "medium",
    category: "auth_bypass",
    cweId: "CWE-617",
    cvssScore: 5.3,
    description:
      "Assert statements are removed when Python runs with optimization (-O flag). Using asserts for security checks means they can be completely bypassed.",
    remediation:
      "Use explicit if/else checks with proper error handling for all security validations. Raise exceptions (PermissionError, HTTPException) instead of using assert.",
    fileExtensions: [".py"],
  },
  {
    id: "py-xxe",
    name: "XML External Entity (XXE) Injection",
    language: "python",
    pattern: /(?:xml\.etree\.ElementTree\.parse|xml\.dom\.minidom\.parse|lxml\.etree\.parse|xml\.sax\.parse)\s*\(/g,
    severity: "high",
    category: "xxe",
    cweId: "CWE-611",
    cvssScore: 7.5,
    description:
      "Python's default XML parsers may process external entities, allowing attackers to read local files, perform SSRF, or cause denial of service.",
    remediation:
      "Use defusedxml library (defusedxml.ElementTree.parse). Disable external entity processing in lxml: parser = etree.XMLParser(resolve_entities=False).",
    fileExtensions: [".py"],
  },
  {
    id: "py-cors-wildcard",
    name: "Permissive CORS Configuration",
    language: "python",
    pattern: /CORS_ORIGIN_ALLOW_ALL\s*=\s*True|allow_origins\s*=\s*\[\s*['"][*]['"]\s*\]/g,
    severity: "medium",
    category: "cors",
    cweId: "CWE-942",
    cvssScore: 5.3,
    description:
      "Allowing all origins for CORS requests exposes the API to cross-origin data theft from any website.",
    remediation:
      "Specify an explicit list of allowed origins. Use CORS_ALLOWED_ORIGINS in Django or origins parameter in FastAPI/Flask-CORS.",
    fileExtensions: [".py"],
  },
];

// ---------------------------------------------------------------------------
// Go Patterns
// ---------------------------------------------------------------------------

export const goPatterns: VulnerabilityPattern[] = [
  {
    id: "go-sql-concat",
    name: "SQL String Concatenation",
    language: "go",
    pattern: /(?:Query|QueryRow|Exec|Prepare)\s*\(\s*(?:fmt\.Sprintf|"[^"]*"\s*\+|\`[^`]*\`\s*\+)/g,
    severity: "critical",
    category: "sqli",
    cweId: "CWE-89",
    cvssScore: 9.8,
    description:
      "Building SQL queries through string concatenation or fmt.Sprintf creates SQL injection vulnerabilities when user input is included.",
    remediation:
      "Use parameterized queries with placeholder arguments: db.Query('SELECT * FROM users WHERE id = $1', id). All Go SQL drivers support parameterized queries.",
    fileExtensions: [".go"],
  },
  {
    id: "go-exec-command",
    name: "Command Injection via exec.Command",
    language: "go",
    pattern: /exec\.Command\s*\(\s*(?:fmt\.Sprintf|"[^"]*"\s*\+|r\.(?:URL|Form|PostForm)|req\.|input)/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-78",
    cvssScore: 9.8,
    description:
      "Building shell commands with user input via exec.Command can lead to command injection if the input is not properly sanitized.",
    remediation:
      "Pass command arguments as separate strings to exec.Command (never concatenate into a single string). Validate input against a strict allowlist.",
    fileExtensions: [".go"],
  },
  {
    id: "go-unsafe-template",
    name: "Unsafe HTML Template Rendering",
    language: "go",
    pattern: /template\.HTML\s*\(/g,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    cvssScore: 6.1,
    description:
      "Casting user input to template.HTML bypasses Go's html/template auto-escaping, enabling cross-site scripting.",
    remediation:
      "Never cast user input to template.HTML. Use html/template's default escaping. If raw HTML is needed, sanitize it with bluemonday before casting.",
    fileExtensions: [".go"],
  },
  {
    id: "go-path-traversal",
    name: "Path Traversal via User Input",
    language: "go",
    pattern: /(?:os\.(?:Open|ReadFile|Create|WriteFile|Remove)|ioutil\.ReadFile|filepath\.Join)\s*\(\s*(?:r\.(?:URL|Form|PostForm)|req\.|input|c\.(?:Param|Query))/g,
    severity: "high",
    category: "lfi",
    cweId: "CWE-22",
    cvssScore: 7.5,
    description:
      "File system operations using unsanitized user input can allow attackers to read or write arbitrary files through path traversal.",
    remediation:
      "Use filepath.Clean() then verify the result with filepath.Rel() to ensure it stays within the intended directory. Use filepath.EvalSymlinks() for additional safety.",
    fileExtensions: [".go"],
  },
  {
    id: "go-ssrf",
    name: "Server-Side Request Forgery",
    language: "go",
    pattern: /http\.(?:Get|Post|Head|NewRequest)\s*\(\s*(?:r\.(?:URL|Form|PostForm)|req\.|input|c\.(?:Param|Query))/g,
    severity: "high",
    category: "ssrf",
    cweId: "CWE-918",
    cvssScore: 7.5,
    description:
      "Making HTTP requests to URLs derived from user input without validation can allow access to internal services and cloud metadata endpoints.",
    remediation:
      "Validate URLs against an allowlist. Parse the URL and check the host against blocked ranges (private IPs, localhost, link-local). Use a custom http.Transport with DialContext restrictions.",
    fileExtensions: [".go"],
  },
  {
    id: "go-hardcoded-secret",
    name: "Hardcoded Secret in Go Code",
    language: "go",
    pattern: /(?:const|var)\s+\w*(?:secret|password|apiKey|token|auth|credential|privateKey)\w*\s*=\s*"[^"]{8,}"/gi,
    severity: "high",
    category: "information_disclosure",
    cweId: "CWE-798",
    cvssScore: 7.5,
    description:
      "Hardcoded secrets in Go source code can be extracted from compiled binaries or source repositories.",
    remediation:
      "Use environment variables via os.Getenv(). Consider viper for configuration management or integrate with a secrets manager.",
    fileExtensions: [".go"],
  },
  {
    id: "go-insecure-tls",
    name: "Insecure TLS Configuration",
    language: "go",
    pattern: /InsecureSkipVerify\s*:\s*true/g,
    severity: "high",
    category: "cryptographic",
    cweId: "CWE-295",
    cvssScore: 7.4,
    description:
      "Setting InsecureSkipVerify to true disables TLS certificate verification, making the connection vulnerable to man-in-the-middle attacks.",
    remediation:
      "Remove InsecureSkipVerify: true. If custom CAs are needed, configure them in tls.Config.RootCAs. For development, use mkcert to generate locally-trusted certificates.",
    fileExtensions: [".go"],
  },
  {
    id: "go-weak-crypto",
    name: "Weak Cryptographic Algorithm",
    language: "go",
    pattern: /(?:md5|sha1|des|rc4)\.New\s*\(/g,
    severity: "medium",
    category: "cryptographic",
    cweId: "CWE-327",
    cvssScore: 5.3,
    description:
      "Using weak cryptographic algorithms (MD5, SHA-1, DES, RC4) for security purposes is insecure due to known attacks.",
    remediation:
      "Use sha256.New() for hashing, aes.NewCipher() for encryption, and golang.org/x/crypto/bcrypt for password hashing.",
    fileExtensions: [".go"],
  },
  {
    id: "go-unhandled-error",
    name: "Unhandled Error Return Value",
    language: "go",
    pattern: /^\s*(?:os|io|http|sql|json|xml|bufio|net)\.\w+\s*\([^)]*\)\s*$/gm,
    severity: "medium",
    category: "information_disclosure",
    cweId: "CWE-391",
    cvssScore: 5.3,
    description:
      "Ignoring error return values can mask security-relevant failures, leading to undefined behavior, data corruption, or security bypasses.",
    remediation:
      "Always handle error return values. Use errcheck or golangci-lint to detect unhandled errors. At minimum, log the error.",
    fileExtensions: [".go"],
  },
  {
    id: "go-race-condition",
    name: "Potential Race Condition on Shared State",
    language: "go",
    pattern: /go\s+func\s*\(\s*\)\s*\{[^}]*(?:map\[|\.Lock\(\)|\.Unlock\(\))/g,
    severity: "medium",
    category: "rce",
    cweId: "CWE-362",
    cvssScore: 5.9,
    description:
      "Accessing shared state (maps, slices, global variables) from goroutines without proper synchronization can cause data races, panics, or security-sensitive inconsistencies.",
    remediation:
      "Use sync.Mutex, sync.RWMutex, or channels for goroutine synchronization. Use sync.Map for concurrent map access. Run tests with -race flag.",
    fileExtensions: [".go"],
  },
  {
    id: "go-cors-wildcard",
    name: "Permissive CORS Configuration",
    language: "go",
    pattern: /AllowAllOrigins\s*:\s*true|AllowOrigins\s*:\s*\[\s*"[*]"\s*\]/g,
    severity: "medium",
    category: "cors",
    cweId: "CWE-942",
    cvssScore: 5.3,
    description:
      "Allowing all CORS origins permits any website to make authenticated cross-origin requests to the API.",
    remediation:
      "Specify explicit allowed origins. Use gin-contrib/cors or rs/cors with an explicit allowlist.",
    fileExtensions: [".go"],
  },
  {
    id: "go-integer-overflow",
    name: "Integer Overflow in Conversion",
    language: "go",
    pattern: /(?:int32|int16|int8|uint16|uint8)\s*\(\s*\w+\s*\)/g,
    severity: "medium",
    category: "rce",
    cweId: "CWE-190",
    cvssScore: 5.3,
    description:
      "Narrowing integer conversions (e.g., int64 to int32) can silently overflow, potentially leading to buffer overflows, incorrect bounds checks, or other security issues.",
    remediation:
      "Always validate the value range before narrowing conversions. Use math.MaxInt32 etc. for bounds checking.",
    fileExtensions: [".go"],
  },
  {
    id: "go-open-redirect",
    name: "Open Redirect",
    language: "go",
    pattern: /http\.Redirect\s*\(\s*\w+\s*,\s*\w+\s*,\s*(?:r\.(?:URL|Form|PostForm)|req\.|input|c\.(?:Param|Query))/g,
    severity: "medium",
    category: "open_redirect",
    cweId: "CWE-601",
    cvssScore: 4.7,
    description:
      "Using user-controlled input as the redirect target in http.Redirect allows attackers to redirect users to malicious sites.",
    remediation:
      "Validate redirect URLs against an allowlist of trusted domains. Only allow relative redirects for internal navigation.",
    fileExtensions: [".go"],
  },
  {
    id: "go-unsafe-package",
    name: "Use of unsafe Package",
    language: "go",
    pattern: /import\s+(?:"unsafe"|unsafe\s+"unsafe")/g,
    severity: "medium",
    category: "rce",
    cweId: "CWE-242",
    cvssScore: 5.3,
    description:
      "The unsafe package bypasses Go's type safety guarantees and memory safety, potentially leading to memory corruption and security vulnerabilities.",
    remediation:
      "Avoid the unsafe package unless absolutely necessary for FFI or performance-critical code. Document the safety invariants. Use go vet to verify.",
    fileExtensions: [".go"],
  },
  {
    id: "go-xxe",
    name: "XML External Entity Injection",
    language: "go",
    pattern: /xml\.NewDecoder\s*\([^)]*\)(?:(?!\.(?:Strict|Entity))[\s\S])*\.Decode/g,
    severity: "high",
    category: "xxe",
    cweId: "CWE-611",
    cvssScore: 7.5,
    description:
      "Go's encoding/xml package may process external entities in XML input, potentially allowing file read or SSRF.",
    remediation:
      "Set decoder.Strict = true and decoder.Entity = xml.HTMLEntity. Consider using a more secure XML parser.",
    fileExtensions: [".go"],
  },
  {
    id: "go-gin-debug",
    name: "Gin Framework in Debug Mode",
    language: "go",
    pattern: /gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)/g,
    severity: "low",
    category: "information_disclosure",
    cweId: "CWE-215",
    cvssScore: 3.7,
    description:
      "Running Gin in debug mode in production exposes detailed error messages, route listings, and debug information.",
    remediation:
      "Set gin.SetMode(gin.ReleaseMode) for production deployments. Use GIN_MODE environment variable.",
    fileExtensions: [".go"],
  },
  {
    id: "go-jwt-none-algo",
    name: "JWT Algorithm None Attack",
    language: "go",
    pattern: /jwt\.Parse\s*\([^)]*func\s*\(\s*token\s*\*jwt\.Token\s*\)/g,
    severity: "high",
    category: "auth_bypass",
    cweId: "CWE-345",
    cvssScore: 7.5,
    description:
      "JWT parsing without strict algorithm validation allows the 'none' algorithm attack, where attackers forge tokens without any signature.",
    remediation:
      "Always validate the signing method in the keyfunc: if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { return error }",
    fileExtensions: [".go"],
  },
  {
    id: "go-http-serve-dir",
    name: "Unrestricted Directory Serving",
    language: "go",
    pattern: /http\.FileServer\s*\(\s*http\.Dir\s*\(/g,
    severity: "medium",
    category: "information_disclosure",
    cweId: "CWE-548",
    cvssScore: 5.3,
    description:
      "Serving a directory with http.FileServer without path restrictions can expose sensitive files (.env, .git, config files) to the internet.",
    remediation:
      "Use a restricted file system or middleware to filter requests. Block access to hidden files and sensitive paths.",
    fileExtensions: [".go"],
  },
  {
    id: "go-defer-unlock-missing",
    name: "Missing Defer on Mutex Unlock",
    language: "go",
    pattern: /\.Lock\(\)(?![\s\S]{0,30}defer[\s\S]{0,30}\.Unlock\(\))/g,
    severity: "low",
    category: "rce",
    cweId: "CWE-667",
    cvssScore: 3.7,
    description:
      "Acquiring a mutex lock without immediately deferring the unlock risks deadlock if a panic or early return occurs before unlock.",
    remediation:
      "Always use defer mu.Unlock() immediately after mu.Lock() to ensure the lock is released on all code paths.",
    fileExtensions: [".go"],
  },
  {
    id: "go-log-sensitive",
    name: "Sensitive Data in Log Output",
    language: "go",
    pattern: /log\.(?:Print|Printf|Println|Fatal|Fatalf)\s*\([^)]*(?:password|secret|token|key|credential|apiKey)/gi,
    severity: "medium",
    category: "information_disclosure",
    cweId: "CWE-532",
    cvssScore: 5.5,
    description:
      "Logging sensitive data (passwords, tokens, API keys) exposes credentials in log files, log aggregation systems, and monitoring dashboards.",
    remediation:
      "Mask or redact sensitive values before logging. Use structured logging with a redaction middleware. Never log full credentials.",
    fileExtensions: [".go"],
  },
];

// ---------------------------------------------------------------------------
// Java Patterns
// ---------------------------------------------------------------------------

export const javaPatterns: VulnerabilityPattern[] = [
  {
    id: "java-sql-concat",
    name: "SQL String Concatenation",
    language: "java",
    pattern: /(?:createStatement|executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*(?:"[^"]*"\s*\+|String\.format)/g,
    severity: "critical",
    category: "sqli",
    cweId: "CWE-89",
    cvssScore: 9.8,
    description:
      "Building SQL queries through string concatenation or String.format creates SQL injection vulnerabilities.",
    remediation:
      "Use PreparedStatement with parameterized queries. Use an ORM like JPA/Hibernate with named parameters.",
    fileExtensions: [".java"],
  },
  {
    id: "java-deserialization",
    name: "Unsafe Java Deserialization",
    language: "java",
    pattern: /(?:ObjectInputStream|XMLDecoder|readObject|readUnshared|fromXML)\s*\(/g,
    severity: "critical",
    category: "deserialization",
    cweId: "CWE-502",
    cvssScore: 9.8,
    description:
      "Java deserialization of untrusted data can execute arbitrary code through gadget chains in common libraries (Commons Collections, Spring, etc.).",
    remediation:
      "Use JSON or Protocol Buffers for serialization. If ObjectInputStream is required, use a ValidatingObjectInputStream with an allowlist of permitted classes.",
    fileExtensions: [".java"],
  },
  {
    id: "java-runtime-exec",
    name: "Runtime.exec() Command Injection",
    language: "java",
    pattern: /Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-78",
    cvssScore: 9.8,
    description:
      "Runtime.exec() with user-controlled input can lead to OS command injection. Java's command parsing has subtle platform-dependent behaviors.",
    remediation:
      "Use ProcessBuilder with explicit argument lists. Never pass user input through shell interpreters. Validate input against a strict allowlist.",
    fileExtensions: [".java"],
  },
  {
    id: "java-processbuilder",
    name: "ProcessBuilder Command Injection",
    language: "java",
    pattern: /new\s+ProcessBuilder\s*\(\s*(?:Arrays\.asList|List\.of|"[^"]*"\s*\+)/g,
    severity: "high",
    category: "rce",
    cweId: "CWE-78",
    cvssScore: 8.1,
    description:
      "ProcessBuilder with user-controlled arguments can allow command injection even without shell interpretation, depending on how arguments are constructed.",
    remediation:
      "Always pass arguments as separate list elements. Never concatenate user input into command strings. Validate input against a strict allowlist.",
    fileExtensions: [".java"],
  },
  {
    id: "java-xxe",
    name: "XML External Entity Injection",
    language: "java",
    pattern: /(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.newInstance\s*\(/g,
    severity: "high",
    category: "xxe",
    cweId: "CWE-611",
    cvssScore: 7.5,
    description:
      "Java XML parsers process external entities by default. Without explicit disabling, attackers can read local files, perform SSRF, or cause denial of service.",
    remediation:
      "Disable DTDs and external entities: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true). Use OWASP's XXE prevention cheat sheet.",
    fileExtensions: [".java"],
  },
  {
    id: "java-path-traversal",
    name: "Path Traversal via User Input",
    language: "java",
    pattern: /new\s+File\s*\(\s*(?:request\.get|req\.get|getParameter|getPathVariable)/g,
    severity: "high",
    category: "lfi",
    cweId: "CWE-22",
    cvssScore: 7.5,
    description:
      "Creating File objects from user input without path validation allows directory traversal attacks to read or write arbitrary files.",
    remediation:
      "Use File.getCanonicalPath() and verify it starts with the expected base directory. Use java.nio.file.Path.normalize() and resolve().",
    fileExtensions: [".java"],
  },
  {
    id: "java-insecure-crypto",
    name: "Insecure Cryptographic Algorithm",
    language: "java",
    pattern: /(?:Cipher\.getInstance|MessageDigest\.getInstance|KeyGenerator\.getInstance)\s*\(\s*"(?:DES|3DES|DESede|RC2|RC4|MD5|SHA-1|Blowfish|AES\/ECB)"/g,
    severity: "medium",
    category: "cryptographic",
    cweId: "CWE-327",
    cvssScore: 5.3,
    description:
      "Using deprecated or weak cryptographic algorithms (DES, 3DES, RC2, RC4, MD5, SHA-1, ECB mode) provides insufficient security.",
    remediation:
      "Use AES/GCM/NoPadding for encryption, SHA-256 or SHA-3 for hashing. For passwords, use BCrypt or Argon2.",
    fileExtensions: [".java"],
  },
  {
    id: "java-hardcoded-secret",
    name: "Hardcoded Secret in Java Code",
    language: "java",
    pattern: /(?:private|public|protected|static|final)\s+String\s+\w*(?:secret|password|apiKey|token|auth|credential|privateKey)\w*\s*=\s*"[^"]{8,}"/gi,
    severity: "high",
    category: "information_disclosure",
    cweId: "CWE-798",
    cvssScore: 7.5,
    description:
      "Hardcoded secrets in Java source code can be extracted from compiled class files, JAR archives, or decompiled bytecode.",
    remediation:
      "Use environment variables, Spring's @Value annotation with externalized properties, or integrate with a secrets manager (Vault, AWS Secrets Manager).",
    fileExtensions: [".java"],
  },
  {
    id: "java-ssrf",
    name: "Server-Side Request Forgery",
    language: "java",
    pattern: /new\s+URL\s*\(\s*(?:request\.get|req\.get|getParameter)/g,
    severity: "high",
    category: "ssrf",
    cweId: "CWE-918",
    cvssScore: 7.5,
    description:
      "Creating URL objects from user-controlled input and opening connections allows attackers to reach internal services.",
    remediation:
      "Validate URLs against an allowlist of permitted hosts. Block private IP ranges, localhost, and link-local addresses.",
    fileExtensions: [".java"],
  },
  {
    id: "java-open-redirect",
    name: "Open Redirect",
    language: "java",
    pattern: /(?:sendRedirect|setHeader\s*\(\s*"Location")\s*\(\s*(?:request\.get|req\.get|getParameter)/g,
    severity: "medium",
    category: "open_redirect",
    cweId: "CWE-601",
    cvssScore: 4.7,
    description:
      "Using user input as a redirect target in sendRedirect or Location header enables phishing attacks.",
    remediation:
      "Validate redirect URLs against a whitelist. Use relative URLs for internal redirects. Never redirect to user-supplied absolute URLs.",
    fileExtensions: [".java"],
  },
  {
    id: "java-xss-servlet",
    name: "XSS in Servlet Response",
    language: "java",
    pattern: /(?:getWriter|getOutputStream)\s*\(\s*\)\.(?:print|write|println)\s*\(\s*(?:request\.get|req\.get|getParameter)/g,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    cvssScore: 6.1,
    description:
      "Writing user input directly to the servlet response without encoding enables reflected cross-site scripting.",
    remediation:
      "Use OWASP Java Encoder: Encode.forHtml(input) before writing to response. Use a templating engine with auto-escaping (Thymeleaf, FreeMarker).",
    fileExtensions: [".java"],
  },
  {
    id: "java-ldap-injection",
    name: "LDAP Injection",
    language: "java",
    pattern: /(?:search|lookup|bind)\s*\(\s*(?:"[^"]*"\s*\+|String\.format)/g,
    severity: "high",
    category: "sqli",
    cweId: "CWE-90",
    cvssScore: 7.5,
    description:
      "Building LDAP queries through string concatenation allows attackers to modify the query logic, potentially bypassing authentication or extracting data.",
    remediation:
      "Use parameterized LDAP searches with proper escaping. Encode special LDAP characters: *, (, ), \\, NUL.",
    fileExtensions: [".java"],
  },
  {
    id: "java-log-injection",
    name: "Log Injection (Log4Shell Pattern)",
    language: "java",
    pattern: /(?:logger|log|LOG)\.(?:info|warn|error|debug|trace|fatal)\s*\(\s*(?:request\.get|req\.get|getParameter)/g,
    severity: "high",
    category: "rce",
    cweId: "CWE-117",
    cvssScore: 8.1,
    description:
      "Logging user input without sanitization can enable log injection attacks. With vulnerable Log4j versions, this can lead to remote code execution (Log4Shell / CVE-2021-44228).",
    remediation:
      "Sanitize log input by removing newlines and JNDI lookup strings. Update Log4j to 2.17.0+. Use parameterized logging: logger.info('User: {}', sanitizedInput).",
    fileExtensions: [".java"],
  },
  {
    id: "java-spring-actuator",
    name: "Exposed Spring Boot Actuator Endpoints",
    language: "java",
    pattern: /management\.endpoints\.web\.exposure\.include\s*=\s*[*]/g,
    severity: "high",
    category: "information_disclosure",
    cweId: "CWE-200",
    cvssScore: 7.5,
    description:
      "Exposing all Spring Boot actuator endpoints can leak sensitive information (environment variables, heap dumps, thread dumps) and may allow shutdown.",
    remediation:
      "Only expose necessary endpoints: management.endpoints.web.exposure.include=health,info. Secure actuator endpoints behind authentication.",
    fileExtensions: [".java", ".properties", ".yml", ".yaml"],
  },
  {
    id: "java-insecure-random",
    name: "Insecure Random Number Generation",
    language: "java",
    pattern: /new\s+(?:java\.util\.)?Random\s*\(/g,
    severity: "medium",
    category: "cryptographic",
    cweId: "CWE-338",
    cvssScore: 5.3,
    description:
      "java.util.Random uses a linear congruential generator that is predictable. Using it for security-sensitive values (tokens, session IDs) is insecure.",
    remediation:
      "Use java.security.SecureRandom for all security-sensitive random number generation.",
    fileExtensions: [".java"],
  },
  {
    id: "java-trust-all-certs",
    name: "TrustManager That Accepts All Certificates",
    language: "java",
    pattern: /X509TrustManager[\s\S]*?checkServerTrusted[\s\S]*?\{\s*\}/g,
    severity: "high",
    category: "cryptographic",
    cweId: "CWE-295",
    cvssScore: 7.4,
    description:
      "An empty checkServerTrusted implementation accepts all TLS certificates, making the connection vulnerable to man-in-the-middle attacks.",
    remediation:
      "Use the default TrustManager. If custom CAs are needed, add them to a KeyStore and create a proper TrustManagerFactory.",
    fileExtensions: [".java"],
  },
  {
    id: "java-cors-wildcard",
    name: "Permissive CORS Configuration",
    language: "java",
    pattern: /(?:addAllowedOrigin|allowedOrigins)\s*\(\s*"[*]"\s*\)/g,
    severity: "medium",
    category: "cors",
    cweId: "CWE-942",
    cvssScore: 5.3,
    description:
      "Allowing all CORS origins exposes the application to cross-origin data theft from any website.",
    remediation:
      "Specify explicit allowed origins in the CORS configuration. Use Spring's @CrossOrigin with explicit origins.",
    fileExtensions: [".java"],
  },
  {
    id: "java-el-injection",
    name: "Expression Language Injection",
    language: "java",
    pattern: /(?:ExpressionFactory|ValueExpression|MethodExpression)[\s\S]*?(?:request\.get|getParameter)/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-917",
    cvssScore: 9.8,
    description:
      "Using user input in Java EL expressions can lead to remote code execution through EL injection.",
    remediation:
      "Never use user input in EL expressions. Parameterize values instead of embedding them in expression strings.",
    fileExtensions: [".java"],
  },
  {
    id: "java-cookie-insecure",
    name: "Insecure Cookie Configuration",
    language: "java",
    pattern: /(?:setSecure\s*\(\s*false|setHttpOnly\s*\(\s*false)/g,
    severity: "medium",
    category: "header_misconfig",
    cweId: "CWE-614",
    cvssScore: 4.3,
    description:
      "Cookies without the Secure flag can be transmitted over HTTP, and without HttpOnly they can be accessed by JavaScript, increasing the risk of session theft.",
    remediation:
      "Set cookie.setSecure(true) and cookie.setHttpOnly(true) for all session and authentication cookies.",
    fileExtensions: [".java"],
  },
  {
    id: "java-weak-password-hash",
    name: "Weak Password Hashing",
    language: "java",
    pattern: /MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-1|SHA1)"\s*\)/g,
    severity: "high",
    category: "cryptographic",
    cweId: "CWE-916",
    cvssScore: 7.5,
    description:
      "Using MD5 or SHA-1 for password hashing is insecure. These algorithms are fast and vulnerable to rainbow table and brute-force attacks.",
    remediation:
      "Use BCrypt, PBKDF2, or Argon2 for password hashing. Spring Security provides BCryptPasswordEncoder.",
    fileExtensions: [".java"],
  },
];

// ---------------------------------------------------------------------------
// PHP Patterns
// ---------------------------------------------------------------------------

export const phpPatterns: VulnerabilityPattern[] = [
  {
    id: "php-eval-injection",
    name: "eval() Code Injection",
    language: "php",
    pattern: /\beval\s*\(/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-95",
    cvssScore: 9.8,
    description:
      "PHP's eval() executes arbitrary PHP code. User input reaching eval enables full remote code execution on the server.",
    remediation:
      "Eliminate eval() usage entirely. Use structured data processing, template engines, or configuration files instead.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-system-exec",
    name: "System Command Execution",
    language: "php",
    pattern: /\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-78",
    cvssScore: 9.8,
    description:
      "PHP's command execution functions (system, exec, passthru, shell_exec, popen, proc_open) with user-controlled input enable OS command injection.",
    remediation:
      "Use escapeshellarg() and escapeshellcmd() for all arguments. Prefer exec() with separate argument handling over system(). Consider using PHP libraries instead of shell commands.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-backtick-exec",
    name: "Backtick Command Execution",
    language: "php",
    pattern: /`[^`]*\$(?:_GET|_POST|_REQUEST|_SERVER|_COOKIE)/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-78",
    cvssScore: 9.8,
    description:
      "PHP backtick operator executes shell commands. User input variables ($_GET, $_POST, etc.) in backtick expressions enable command injection.",
    remediation:
      "Never use backtick operator with user input. Use escapeshellarg() or avoid shell commands entirely.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-sql-concat",
    name: "SQL String Concatenation",
    language: "php",
    pattern: /(?:mysql_query|mysqli_query|pg_query|\$\w+->query|\$\w+->exec)\s*\(\s*(?:"[^"]*\$|'[^']*'\s*\.\s*\$|\$\w+\s*\.\s*)/g,
    severity: "critical",
    category: "sqli",
    cweId: "CWE-89",
    cvssScore: 9.8,
    description:
      "Building SQL queries through PHP string interpolation or concatenation with variables creates SQL injection vulnerabilities.",
    remediation:
      "Use PDO prepared statements with placeholders: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$id]);",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-file-inclusion",
    name: "File Inclusion via User Input",
    language: "php",
    pattern: /(?:include|include_once|require|require_once)\s*(?:\(\s*)?(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$\w+)/g,
    severity: "critical",
    category: "lfi",
    cweId: "CWE-98",
    cvssScore: 9.8,
    description:
      "Including files based on user input enables Local File Inclusion (LFI) and Remote File Inclusion (RFI) attacks, potentially leading to code execution.",
    remediation:
      "Use a whitelist of allowed include files. Never use user input directly in include statements. Disable allow_url_include in php.ini.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-unserialize",
    name: "Unsafe Deserialization",
    language: "php",
    pattern: /\bunserialize\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$\w+\s*(?:\[|->))/g,
    severity: "critical",
    category: "deserialization",
    cweId: "CWE-502",
    cvssScore: 9.8,
    description:
      "PHP's unserialize() on untrusted data can trigger __wakeup/__destruct magic methods in gadget chains, leading to remote code execution.",
    remediation:
      "Use json_encode/json_decode instead of serialize/unserialize for data interchange. If unserialize is required, use the allowed_classes option to restrict types.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-xss-echo",
    name: "XSS via Unescaped Output",
    language: "php",
    pattern: /(?:echo|print|printf)\s+(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER\s*\[\s*['"](?:HTTP_|REQUEST_URI|QUERY_STRING|PATH_INFO))/g,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    cvssScore: 6.1,
    description:
      "Echoing user input ($_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER) without HTML encoding enables reflected cross-site scripting attacks.",
    remediation:
      "Always use htmlspecialchars($input, ENT_QUOTES, 'UTF-8') when outputting user data in HTML context. Use a templating engine with auto-escaping (Twig, Blade).",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-path-traversal",
    name: "Path Traversal",
    language: "php",
    pattern: /(?:file_get_contents|file_put_contents|fopen|readfile|file|copy|rename|unlink|mkdir|rmdir)\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST)/g,
    severity: "high",
    category: "lfi",
    cweId: "CWE-22",
    cvssScore: 7.5,
    description:
      "File operations using unsanitized user input allow path traversal attacks to read, write, or delete arbitrary files.",
    remediation:
      "Use realpath() and verify the result starts with the expected base directory. Use basename() to strip directory components. Validate against a whitelist.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-hardcoded-secret",
    name: "Hardcoded Secret in PHP Code",
    language: "php",
    pattern: /\$\w*(?:secret|password|passwd|api_?key|token|auth|credential)\w*\s*=\s*['"][^'"]{8,}['"]/gi,
    severity: "high",
    category: "information_disclosure",
    cweId: "CWE-798",
    cvssScore: 7.5,
    description:
      "Hardcoded secrets in PHP source code can be extracted from the repository or exposed if the web server serves .php files as plain text.",
    remediation:
      "Use environment variables ($_ENV, getenv()) or a configuration file outside the web root. Use a secrets manager in production.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-deprecated-mysql",
    name: "Deprecated mysql_* Functions",
    language: "php",
    pattern: /\bmysql_(?:connect|query|fetch_array|fetch_row|fetch_assoc|num_rows|real_escape_string)\s*\(/g,
    severity: "high",
    category: "sqli",
    cweId: "CWE-477",
    cvssScore: 7.5,
    description:
      "The mysql_* extension was removed in PHP 7.0. These functions lack prepared statement support and are inherently vulnerable to SQL injection.",
    remediation:
      "Migrate to PDO or MySQLi with prepared statements. PDO provides a consistent interface across database drivers.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-extract-superglobal",
    name: "extract() on Superglobals",
    language: "php",
    pattern: /\bextract\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-621",
    cvssScore: 9.1,
    description:
      "Using extract() on superglobals imports user-controlled variables into the local scope, potentially overwriting security-critical variables.",
    remediation:
      "Never use extract() on user input. Access superglobal values explicitly: $_GET['key']. Use EXTR_SKIP or EXTR_PREFIX_ALL if extract is unavoidable.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-ssrf",
    name: "Server-Side Request Forgery",
    language: "php",
    pattern: /(?:file_get_contents|curl_setopt|fopen|readfile)\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$url|\$target|\$host)/g,
    severity: "high",
    category: "ssrf",
    cweId: "CWE-918",
    cvssScore: 7.5,
    description:
      "PHP file functions and curl with user-controlled URLs can be used to probe internal networks and access cloud metadata endpoints.",
    remediation:
      "Validate URLs against an allowlist. Parse the URL and verify the host. Block private IP ranges. Disable allow_url_fopen if not needed.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-weak-hash",
    name: "Weak Password Hashing",
    language: "php",
    pattern: /(?:md5|sha1|crc32)\s*\(\s*\$\w*(?:pass|password|passwd)/gi,
    severity: "high",
    category: "cryptographic",
    cweId: "CWE-916",
    cvssScore: 7.5,
    description:
      "Using MD5, SHA-1, or CRC32 for password hashing is insecure. These are fast algorithms vulnerable to brute-force and rainbow table attacks.",
    remediation:
      "Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID. Verify with password_verify().",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-preg-eval",
    name: "preg_replace with /e Modifier",
    language: "php",
    pattern: /preg_replace\s*\(\s*['"]\/[^'"]*\/e['"]/g,
    severity: "critical",
    category: "rce",
    cweId: "CWE-95",
    cvssScore: 9.8,
    description:
      "The /e modifier in preg_replace evaluates the replacement string as PHP code. This is deprecated and extremely dangerous with user input.",
    remediation:
      "Use preg_replace_callback() instead of the /e modifier. The /e modifier was removed in PHP 7.0.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-insecure-upload",
    name: "Insecure File Upload",
    language: "php",
    pattern: /move_uploaded_file\s*\(\s*\$_FILES\s*\[/g,
    severity: "high",
    category: "rce",
    cweId: "CWE-434",
    cvssScore: 8.8,
    description:
      "File upload handling without proper validation of file type, size, and content can allow attackers to upload malicious scripts.",
    remediation:
      "Validate file extension against an allowlist. Check MIME type and file content. Store uploads outside the web root with randomized names. Set proper permissions.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-open-redirect",
    name: "Open Redirect",
    language: "php",
    pattern: /header\s*\(\s*['"]Location\s*:\s*['"]?\s*\.\s*(?:\$_GET|\$_POST|\$_REQUEST)/g,
    severity: "medium",
    category: "open_redirect",
    cweId: "CWE-601",
    cvssScore: 4.7,
    description:
      "Using user input in the Location header without validation enables open redirect attacks for phishing.",
    remediation:
      "Validate redirect URLs against a whitelist. Use relative paths for internal redirects. Parse the URL and verify the host.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-session-fixation",
    name: "Missing Session Regeneration",
    language: "php",
    pattern: /\$_SESSION\s*\[\s*['"](?:user|logged_in|authenticated|admin|role)['"]\s*\]\s*=/g,
    severity: "medium",
    category: "auth_bypass",
    cweId: "CWE-384",
    cvssScore: 5.4,
    description:
      "Setting session authentication values without regenerating the session ID enables session fixation attacks.",
    remediation:
      "Call session_regenerate_id(true) before setting authentication session values. This prevents session fixation.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-xxe",
    name: "XML External Entity Injection",
    language: "php",
    pattern: /(?:simplexml_load_string|DOMDocument|XMLReader).*(?:loadXML|load)\s*\(/g,
    severity: "high",
    category: "xxe",
    cweId: "CWE-611",
    cvssScore: 7.5,
    description:
      "PHP XML parsers process external entities by default (prior to PHP 8.0). Without libxml_disable_entity_loader(), XXE attacks are possible.",
    remediation:
      "Call libxml_disable_entity_loader(true) before parsing (PHP < 8.0). Use LIBXML_NOENT|LIBXML_DTDLOAD flags carefully. Upgrade to PHP 8.0+ where external entities are disabled by default.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-cors-wildcard",
    name: "Permissive CORS Configuration",
    language: "php",
    pattern: /header\s*\(\s*['"]Access-Control-Allow-Origin\s*:\s*[*]['"]\s*\)/g,
    severity: "medium",
    category: "cors",
    cweId: "CWE-942",
    cvssScore: 5.3,
    description:
      "Setting Access-Control-Allow-Origin to '*' allows any website to make cross-origin requests.",
    remediation:
      "Validate the Origin header against an allowlist and only reflect trusted origins. Never use wildcard with credentials.",
    fileExtensions: [".php", ".phtml"],
  },
  {
    id: "php-type-juggling",
    name: "Loose Comparison Type Juggling",
    language: "php",
    pattern: /(?:\$\w*(?:pass|password|token|hash|secret|key)\w*\s*==\s*(?:\$|['"]))|(?:(?:\$|['"])\w*\s*==\s*\$\w*(?:pass|password|token|hash|secret|key))/gi,
    severity: "high",
    category: "auth_bypass",
    cweId: "CWE-697",
    cvssScore: 7.5,
    description:
      "PHP's loose comparison (==) performs type juggling that can bypass authentication checks (e.g., '0e123' == '0e456' evaluates to true).",
    remediation:
      "Always use strict comparison (===) for security-sensitive comparisons. Use hash_equals() for timing-safe hash comparison.",
    fileExtensions: [".php", ".phtml"],
  },
];

// ---------------------------------------------------------------------------
// Aggregated Pattern Map
// ---------------------------------------------------------------------------

/** All patterns indexed by language for quick lookup */
export const patternsByLanguage: Record<string, VulnerabilityPattern[]> = {
  javascript: jsPatterns,
  typescript: jsPatterns, // TS shares JS patterns
  python: pythonPatterns,
  go: goPatterns,
  java: javaPatterns,
  php: phpPatterns,
};

/** Flat array of all vulnerability patterns across all languages */
export const allPatterns: VulnerabilityPattern[] = [
  ...jsPatterns,
  ...pythonPatterns,
  ...goPatterns,
  ...javaPatterns,
  ...phpPatterns,
];

/**
 * Maps file extensions to their corresponding language key in patternsByLanguage.
 */
export const extensionToLanguage: Record<string, string> = {
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".py": "python",
  ".pyw": "python",
  ".go": "go",
  ".java": "java",
  ".php": "php",
  ".phtml": "php",
};
