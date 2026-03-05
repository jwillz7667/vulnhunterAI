/**
 * Compliance Framework Mapping Engine
 * Maps vulnerabilities to OWASP Top 10, NIST, PCI-DSS, SOC 2, ISO 27001 controls.
 */

export interface ComplianceControl {
  id: string;
  name: string;
  description: string;
  status: "pass" | "fail" | "partial" | "not_applicable";
  findingIds: string[];
}

export interface ComplianceResult {
  framework: string;
  version: string;
  overallScore: number;
  controls: ComplianceControl[];
  summary: string;
}

interface VulnInput {
  id: string;
  category: string;
  severity: string;
  cweId?: string;
}

// OWASP Top 10 2021
const OWASP_CONTROLS: Array<{ id: string; name: string; description: string; categories: string[] }> = [
  { id: "A01:2021", name: "Broken Access Control", description: "Restrictions on authenticated users are not properly enforced.", categories: ["idor", "auth_bypass", "cors", "open_redirect", "cloud_misconfig"] },
  { id: "A02:2021", name: "Cryptographic Failures", description: "Failures related to cryptography leading to exposure of sensitive data.", categories: ["cryptographic", "ssl_tls", "network_misconfig"] },
  { id: "A03:2021", name: "Injection", description: "User-supplied data is not validated, filtered, or sanitized.", categories: ["xss", "sqli", "rce", "lfi", "xxe", "api_vuln"] },
  { id: "A04:2021", name: "Insecure Design", description: "Missing or ineffective control design.", categories: ["business_logic"] },
  { id: "A05:2021", name: "Security Misconfiguration", description: "Missing appropriate security hardening.", categories: ["header_misconfig", "graphql", "information_disclosure"] },
  { id: "A06:2021", name: "Vulnerable and Outdated Components", description: "Components with known vulnerabilities.", categories: ["dependency"] },
  { id: "A07:2021", name: "Identification and Authentication Failures", description: "Authentication and session management weaknesses.", categories: ["auth_bypass", "secret_exposure"] },
  { id: "A08:2021", name: "Software and Data Integrity Failures", description: "Code and infrastructure without integrity verification.", categories: ["deserialization"] },
  { id: "A09:2021", name: "Security Logging and Monitoring Failures", description: "Insufficient logging, detection, monitoring, and response.", categories: [] },
  { id: "A10:2021", name: "Server-Side Request Forgery", description: "Web application fetches a remote resource without validating user-supplied URL.", categories: ["ssrf"] },
];

// PCI-DSS v4.0 relevant controls
const PCI_CONTROLS: Array<{ id: string; name: string; description: string; categories: string[] }> = [
  { id: "6.2.4", name: "Software Engineering Techniques", description: "Prevent common software attacks.", categories: ["xss", "sqli", "rce", "ssrf", "xxe", "lfi"] },
  { id: "6.3.1", name: "Security Vulnerabilities Identified", description: "Known vulnerabilities must be addressed.", categories: ["dependency"] },
  { id: "6.4.1", name: "Public-Facing Web Applications Protection", description: "Protect against known attacks.", categories: ["xss", "sqli", "cors", "header_misconfig"] },
  { id: "2.2.7", name: "Non-Console Administrative Access Encryption", description: "Encrypt non-console admin access.", categories: ["ssl_tls", "cryptographic"] },
  { id: "4.2.1", name: "Strong Cryptography for Transmission", description: "Protect cardholder data during transmission.", categories: ["ssl_tls", "cryptographic", "network_misconfig"] },
  { id: "7.2.1", name: "Access Control System", description: "Restrict access based on need-to-know.", categories: ["idor", "auth_bypass", "cloud_misconfig"] },
  { id: "8.3.1", name: "Authentication Factor Management", description: "Strong authentication mechanisms.", categories: ["auth_bypass", "secret_exposure"] },
  { id: "11.3.1", name: "Vulnerability Scanning", description: "Regular vulnerability scanning.", categories: [] },
];

// NIST 800-53 relevant controls
const NIST_CONTROLS: Array<{ id: string; name: string; description: string; categories: string[] }> = [
  { id: "AC-3", name: "Access Enforcement", description: "Enforce approved authorizations for logical access.", categories: ["idor", "auth_bypass", "cors", "cloud_misconfig"] },
  { id: "AC-6", name: "Least Privilege", description: "Employ principle of least privilege.", categories: ["idor", "auth_bypass", "cloud_misconfig"] },
  { id: "IA-2", name: "Identification and Authentication", description: "Uniquely identify and authenticate organizational users.", categories: ["auth_bypass", "secret_exposure"] },
  { id: "SC-8", name: "Transmission Confidentiality", description: "Protect confidentiality of transmitted information.", categories: ["ssl_tls", "cryptographic", "network_misconfig"] },
  { id: "SC-13", name: "Cryptographic Protection", description: "Implement cryptographic mechanisms.", categories: ["cryptographic", "ssl_tls"] },
  { id: "SI-10", name: "Information Input Validation", description: "Check validity of information inputs.", categories: ["xss", "sqli", "rce", "ssrf", "xxe", "lfi", "api_vuln"] },
  { id: "SI-11", name: "Error Handling", description: "Generate error messages providing necessary information without revealing exploitable details.", categories: ["information_disclosure"] },
  { id: "SA-11", name: "Developer Security Testing", description: "Require security testing of developed software.", categories: ["dependency"] },
  { id: "CM-6", name: "Configuration Settings", description: "Establish mandatory configuration settings.", categories: ["header_misconfig", "cloud_misconfig", "network_misconfig"] },
  { id: "RA-5", name: "Vulnerability Monitoring and Scanning", description: "Monitor and scan for vulnerabilities.", categories: [] },
];

// SOC 2 Trust Service Criteria
const SOC2_CONTROLS: Array<{ id: string; name: string; description: string; categories: string[] }> = [
  { id: "CC6.1", name: "Logical Access Security", description: "Logical access security implemented.", categories: ["idor", "auth_bypass", "cloud_misconfig"] },
  { id: "CC6.6", name: "External Threats", description: "System operations protected against external threats.", categories: ["xss", "sqli", "ssrf", "rce"] },
  { id: "CC6.7", name: "Data Transmission", description: "Data transmission restricted to authorized users.", categories: ["ssl_tls", "cryptographic", "cors"] },
  { id: "CC7.1", name: "Threat Detection", description: "Detection of anomalies in infrastructure and software.", categories: ["header_misconfig", "network_misconfig"] },
  { id: "CC8.1", name: "Change Management", description: "Changes to systems authorized, designed, and implemented.", categories: ["dependency"] },
];

// ISO 27001:2022 controls
const ISO27001_CONTROLS: Array<{ id: string; name: string; description: string; categories: string[] }> = [
  { id: "A.8.3", name: "Information Access Restriction", description: "Access to information restricted by policy.", categories: ["idor", "auth_bypass", "cloud_misconfig"] },
  { id: "A.8.9", name: "Configuration Management", description: "Configurations managed across the technology estate.", categories: ["header_misconfig", "cloud_misconfig", "network_misconfig"] },
  { id: "A.8.26", name: "Application Security Requirements", description: "Security requirements for applications identified.", categories: ["xss", "sqli", "ssrf", "rce", "xxe"] },
  { id: "A.8.28", name: "Secure Coding", description: "Secure coding principles applied to development.", categories: ["xss", "sqli", "deserialization", "lfi"] },
  { id: "A.8.8", name: "Management of Technical Vulnerabilities", description: "Technical vulnerabilities identified and managed.", categories: ["dependency"] },
  { id: "A.8.24", name: "Use of Cryptography", description: "Cryptographic controls implemented.", categories: ["cryptographic", "ssl_tls"] },
];

export function mapToCompliance(
  framework: string,
  vulnerabilities: VulnInput[]
): ComplianceResult {
  switch (framework.toLowerCase()) {
    case "owasp_top10":
    case "owasp":
      return evaluateControls("OWASP Top 10", "2021", OWASP_CONTROLS, vulnerabilities);
    case "pci_dss":
    case "pci":
      return evaluateControls("PCI-DSS", "4.0", PCI_CONTROLS, vulnerabilities);
    case "nist":
    case "nist_800_53":
      return evaluateControls("NIST 800-53", "Rev. 5", NIST_CONTROLS, vulnerabilities);
    case "soc2":
      return evaluateControls("SOC 2", "2022", SOC2_CONTROLS, vulnerabilities);
    case "iso27001":
    case "iso":
      return evaluateControls("ISO 27001", "2022", ISO27001_CONTROLS, vulnerabilities);
    default:
      throw new Error(`Unknown compliance framework: ${framework}`);
  }
}

function evaluateControls(
  frameworkName: string,
  version: string,
  controlDefs: Array<{ id: string; name: string; description: string; categories: string[] }>,
  vulnerabilities: VulnInput[]
): ComplianceResult {
  const controls: ComplianceControl[] = controlDefs.map((def) => {
    const matchingVulns = vulnerabilities.filter((v) =>
      def.categories.includes(v.category.toLowerCase())
    );

    const findingIds = matchingVulns.map((v) => v.id);
    const hasCriticalOrHigh = matchingVulns.some(
      (v) => v.severity === "critical" || v.severity === "high"
    );

    let status: ComplianceControl["status"];
    if (def.categories.length === 0) {
      status = "not_applicable";
    } else if (matchingVulns.length === 0) {
      status = "pass";
    } else if (hasCriticalOrHigh) {
      status = "fail";
    } else {
      status = "partial";
    }

    return {
      id: def.id,
      name: def.name,
      description: def.description,
      status,
      findingIds,
    };
  });

  const applicable = controls.filter((c) => c.status !== "not_applicable");
  const passing = applicable.filter((c) => c.status === "pass");
  const overallScore =
    applicable.length > 0
      ? Math.round((passing.length / applicable.length) * 100)
      : 100;

  const failCount = controls.filter((c) => c.status === "fail").length;
  const partialCount = controls.filter((c) => c.status === "partial").length;

  return {
    framework: frameworkName,
    version,
    overallScore,
    controls,
    summary:
      failCount > 0
        ? `${failCount} control(s) failing, ${partialCount} partial. Immediate remediation required.`
        : partialCount > 0
          ? `${partialCount} control(s) partially met. Review and remediate low-severity findings.`
          : `All applicable controls passing. Compliance posture is strong.`,
  };
}

export function getSupportedFrameworks(): string[] {
  return ["owasp_top10", "pci_dss", "nist", "soc2", "iso27001"];
}
