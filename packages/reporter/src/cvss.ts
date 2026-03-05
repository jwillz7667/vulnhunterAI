/**
 * CVSS v3.1 Calculator
 * Implements the Common Vulnerability Scoring System specification.
 */

export interface CvssMetrics {
  // Base Metrics
  attackVector: "N" | "A" | "L" | "P"; // Network, Adjacent, Local, Physical
  attackComplexity: "L" | "H"; // Low, High
  privilegesRequired: "N" | "L" | "H"; // None, Low, High
  userInteraction: "N" | "R"; // None, Required
  scope: "U" | "C"; // Unchanged, Changed
  confidentialityImpact: "N" | "L" | "H"; // None, Low, High
  integrityImpact: "N" | "L" | "H";
  availabilityImpact: "N" | "L" | "H";
}

export interface CvssResult {
  score: number;
  severity: "none" | "low" | "medium" | "high" | "critical";
  vector: string;
}

const AV_VALUES: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_VALUES: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_VALUES_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_VALUES_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.50 };
const UI_VALUES: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA_VALUES: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

export function calculateCvss(metrics: CvssMetrics): CvssResult {
  const vector = buildVector(metrics);

  const av = AV_VALUES[metrics.attackVector];
  const ac = AC_VALUES[metrics.attackComplexity];
  const pr =
    metrics.scope === "C"
      ? PR_VALUES_CHANGED[metrics.privilegesRequired]
      : PR_VALUES_UNCHANGED[metrics.privilegesRequired];
  const ui = UI_VALUES[metrics.userInteraction];

  const exploitability = 8.22 * av * ac * pr * ui;

  const cI = CIA_VALUES[metrics.confidentialityImpact];
  const iI = CIA_VALUES[metrics.integrityImpact];
  const aI = CIA_VALUES[metrics.availabilityImpact];

  const iscBase = 1 - (1 - cI) * (1 - iI) * (1 - aI);
  const impact =
    metrics.scope === "U"
      ? 6.42 * iscBase
      : 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);

  let score: number;
  if (impact <= 0) {
    score = 0;
  } else if (metrics.scope === "U") {
    score = roundUp(Math.min(impact + exploitability, 10));
  } else {
    score = roundUp(Math.min(1.08 * (impact + exploitability), 10));
  }

  return {
    score,
    severity: getSeverity(score),
    vector,
  };
}

export function calculateCvssFromVector(vector: string): CvssResult {
  const metrics = parseVector(vector);
  return calculateCvss(metrics);
}

export function buildVector(metrics: CvssMetrics): string {
  return (
    `CVSS:3.1/AV:${metrics.attackVector}/AC:${metrics.attackComplexity}` +
    `/PR:${metrics.privilegesRequired}/UI:${metrics.userInteraction}` +
    `/S:${metrics.scope}/C:${metrics.confidentialityImpact}` +
    `/I:${metrics.integrityImpact}/A:${metrics.availabilityImpact}`
  );
}

export function parseVector(vector: string): CvssMetrics {
  const parts = vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/");
  const map: Record<string, string> = {};
  for (const part of parts) {
    const [key, value] = part.split(":");
    map[key] = value;
  }

  return {
    attackVector: map.AV as CvssMetrics["attackVector"],
    attackComplexity: map.AC as CvssMetrics["attackComplexity"],
    privilegesRequired: map.PR as CvssMetrics["privilegesRequired"],
    userInteraction: map.UI as CvssMetrics["userInteraction"],
    scope: map.S as CvssMetrics["scope"],
    confidentialityImpact: map.C as CvssMetrics["confidentialityImpact"],
    integrityImpact: map.I as CvssMetrics["integrityImpact"],
    availabilityImpact: map.A as CvssMetrics["availabilityImpact"],
  };
}

export function getSeverity(score: number): "none" | "low" | "medium" | "high" | "critical" {
  if (score === 0) return "none";
  if (score < 4.0) return "low";
  if (score < 7.0) return "medium";
  if (score < 9.0) return "high";
  return "critical";
}

export function estimateCvss(
  category: string,
  confirmed: boolean
): CvssResult {
  const defaults: Record<string, CvssMetrics> = {
    xss: {
      attackVector: "N", attackComplexity: "L", privilegesRequired: "N",
      userInteraction: "R", scope: "C", confidentialityImpact: "L",
      integrityImpact: "L", availabilityImpact: "N",
    },
    sqli: {
      attackVector: "N", attackComplexity: "L", privilegesRequired: "N",
      userInteraction: "N", scope: "U", confidentialityImpact: "H",
      integrityImpact: "H", availabilityImpact: "H",
    },
    ssrf: {
      attackVector: "N", attackComplexity: "L", privilegesRequired: "N",
      userInteraction: "N", scope: "C", confidentialityImpact: "H",
      integrityImpact: "N", availabilityImpact: "N",
    },
    rce: {
      attackVector: "N", attackComplexity: "L", privilegesRequired: "N",
      userInteraction: "N", scope: "U", confidentialityImpact: "H",
      integrityImpact: "H", availabilityImpact: "H",
    },
    idor: {
      attackVector: "N", attackComplexity: "L", privilegesRequired: "L",
      userInteraction: "N", scope: "U", confidentialityImpact: "H",
      integrityImpact: "L", availabilityImpact: "N",
    },
    auth_bypass: {
      attackVector: "N", attackComplexity: "L", privilegesRequired: "N",
      userInteraction: "N", scope: "U", confidentialityImpact: "H",
      integrityImpact: "H", availabilityImpact: "N",
    },
    cors: {
      attackVector: "N", attackComplexity: "L", privilegesRequired: "N",
      userInteraction: "R", scope: "U", confidentialityImpact: "H",
      integrityImpact: "N", availabilityImpact: "N",
    },
    header_misconfig: {
      attackVector: "N", attackComplexity: "L", privilegesRequired: "N",
      userInteraction: "N", scope: "U", confidentialityImpact: "N",
      integrityImpact: "L", availabilityImpact: "N",
    },
    information_disclosure: {
      attackVector: "N", attackComplexity: "L", privilegesRequired: "N",
      userInteraction: "N", scope: "U", confidentialityImpact: "L",
      integrityImpact: "N", availabilityImpact: "N",
    },
  };

  const metrics = defaults[category.toLowerCase()] || defaults.information_disclosure;
  return calculateCvss(metrics);
}

function roundUp(value: number): number {
  return Math.ceil(value * 10) / 10;
}
