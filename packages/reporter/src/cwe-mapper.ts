/**
 * CWE (Common Weakness Enumeration) Classification Mapper
 * Maps vulnerability categories to CWE IDs with descriptions.
 */

export interface CweEntry {
  id: string;
  name: string;
  description: string;
  url: string;
  category: string;
  owaspTop10?: string;
}

const CWE_DATABASE: CweEntry[] = [
  // Injection
  { id: "CWE-79", name: "Improper Neutralization of Input During Web Page Generation", description: "Cross-site scripting (XSS) vulnerability allows injection of client-side scripts.", url: "https://cwe.mitre.org/data/definitions/79.html", category: "xss", owaspTop10: "A03:2021" },
  { id: "CWE-89", name: "Improper Neutralization of Special Elements used in an SQL Command", description: "SQL injection allows manipulation of SQL queries through user input.", url: "https://cwe.mitre.org/data/definitions/89.html", category: "sqli", owaspTop10: "A03:2021" },
  { id: "CWE-918", name: "Server-Side Request Forgery (SSRF)", description: "Application fetches remote resources without validating user-supplied URLs.", url: "https://cwe.mitre.org/data/definitions/918.html", category: "ssrf", owaspTop10: "A10:2021" },
  { id: "CWE-78", name: "Improper Neutralization of Special Elements used in an OS Command", description: "OS command injection through unsanitized input.", url: "https://cwe.mitre.org/data/definitions/78.html", category: "rce", owaspTop10: "A03:2021" },
  { id: "CWE-611", name: "Improper Restriction of XML External Entity Reference", description: "XXE vulnerability allows external entity processing in XML input.", url: "https://cwe.mitre.org/data/definitions/611.html", category: "xxe", owaspTop10: "A05:2021" },

  // Broken Access Control
  { id: "CWE-639", name: "Authorization Bypass Through User-Controlled Key", description: "IDOR allows unauthorized access by manipulating resource identifiers.", url: "https://cwe.mitre.org/data/definitions/639.html", category: "idor", owaspTop10: "A01:2021" },
  { id: "CWE-287", name: "Improper Authentication", description: "Authentication bypass allows unauthorized access.", url: "https://cwe.mitre.org/data/definitions/287.html", category: "auth_bypass", owaspTop10: "A07:2021" },
  { id: "CWE-942", name: "Permissive Cross-domain Policy with Untrusted Domains", description: "CORS misconfiguration allows unauthorized cross-origin access.", url: "https://cwe.mitre.org/data/definitions/942.html", category: "cors", owaspTop10: "A05:2021" },
  { id: "CWE-601", name: "URL Redirection to Untrusted Site", description: "Open redirect allows redirection to attacker-controlled sites.", url: "https://cwe.mitre.org/data/definitions/601.html", category: "open_redirect", owaspTop10: "A01:2021" },

  // Security Misconfiguration
  { id: "CWE-16", name: "Configuration", description: "Security misconfiguration in headers or server settings.", url: "https://cwe.mitre.org/data/definitions/16.html", category: "header_misconfig", owaspTop10: "A05:2021" },
  { id: "CWE-693", name: "Protection Mechanism Failure", description: "Missing or misconfigured security controls.", url: "https://cwe.mitre.org/data/definitions/693.html", category: "header_misconfig", owaspTop10: "A05:2021" },

  // Cryptographic Issues
  { id: "CWE-327", name: "Use of a Broken or Risky Cryptographic Algorithm", description: "Weak cryptographic algorithm usage.", url: "https://cwe.mitre.org/data/definitions/327.html", category: "cryptographic", owaspTop10: "A02:2021" },
  { id: "CWE-295", name: "Improper Certificate Validation", description: "SSL/TLS certificate validation issues.", url: "https://cwe.mitre.org/data/definitions/295.html", category: "ssl_tls", owaspTop10: "A02:2021" },

  // Information Disclosure
  { id: "CWE-200", name: "Exposure of Sensitive Information to an Unauthorized Actor", description: "Information disclosure through error messages, headers, or responses.", url: "https://cwe.mitre.org/data/definitions/200.html", category: "information_disclosure", owaspTop10: "A01:2021" },
  { id: "CWE-209", name: "Generation of Error Message Containing Sensitive Information", description: "Detailed error messages expose internal information.", url: "https://cwe.mitre.org/data/definitions/209.html", category: "information_disclosure", owaspTop10: "A05:2021" },
  { id: "CWE-798", name: "Use of Hard-coded Credentials", description: "Credentials embedded in source code.", url: "https://cwe.mitre.org/data/definitions/798.html", category: "secret_exposure", owaspTop10: "A07:2021" },

  // Deserialization
  { id: "CWE-502", name: "Deserialization of Untrusted Data", description: "Unsafe deserialization can lead to remote code execution.", url: "https://cwe.mitre.org/data/definitions/502.html", category: "deserialization", owaspTop10: "A08:2021" },

  // API
  { id: "CWE-20", name: "Improper Input Validation", description: "Insufficient input validation on API endpoints.", url: "https://cwe.mitre.org/data/definitions/20.html", category: "api_vuln", owaspTop10: "A03:2021" },

  // GraphQL
  { id: "CWE-400", name: "Uncontrolled Resource Consumption", description: "GraphQL query depth or batch attacks causing DoS.", url: "https://cwe.mitre.org/data/definitions/400.html", category: "graphql", owaspTop10: "A05:2021" },

  // File Inclusion
  { id: "CWE-98", name: "Improper Control of Filename for Include/Require Statement", description: "Local file inclusion through path manipulation.", url: "https://cwe.mitre.org/data/definitions/98.html", category: "lfi", owaspTop10: "A03:2021" },

  // Business Logic
  { id: "CWE-840", name: "Business Logic Errors", description: "Flaws in application business logic.", url: "https://cwe.mitre.org/data/definitions/840.html", category: "business_logic", owaspTop10: "A04:2021" },

  // Smart Contract
  { id: "CWE-841", name: "Improper Enforcement of Behavioral Workflow", description: "Smart contract reentrancy and state management issues.", url: "https://cwe.mitre.org/data/definitions/841.html", category: "smart_contract" },

  // Dependency
  { id: "CWE-1104", name: "Use of Unmaintained Third Party Components", description: "Vulnerable or outdated dependencies.", url: "https://cwe.mitre.org/data/definitions/1104.html", category: "dependency", owaspTop10: "A06:2021" },

  // Cloud
  { id: "CWE-284", name: "Improper Access Control", description: "Cloud resource misconfiguration allowing unauthorized access.", url: "https://cwe.mitre.org/data/definitions/284.html", category: "cloud_misconfig", owaspTop10: "A01:2021" },

  // Network
  { id: "CWE-311", name: "Missing Encryption of Sensitive Data", description: "Network communications lacking encryption.", url: "https://cwe.mitre.org/data/definitions/311.html", category: "network_misconfig", owaspTop10: "A02:2021" },
];

export function getCweForCategory(category: string): CweEntry | undefined {
  return CWE_DATABASE.find(
    (e) => e.category.toLowerCase() === category.toLowerCase()
  );
}

export function getCweById(cweId: string): CweEntry | undefined {
  const normalizedId = cweId.startsWith("CWE-") ? cweId : `CWE-${cweId}`;
  return CWE_DATABASE.find((e) => e.id === normalizedId);
}

export function getAllCwesForCategory(category: string): CweEntry[] {
  return CWE_DATABASE.filter(
    (e) => e.category.toLowerCase() === category.toLowerCase()
  );
}

export function getOwaspMapping(cweId: string): string | undefined {
  return getCweById(cweId)?.owaspTop10;
}

export function getAllCweEntries(): CweEntry[] {
  return [...CWE_DATABASE];
}
