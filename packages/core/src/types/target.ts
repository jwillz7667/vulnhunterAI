import { z } from "zod";

// ---------------------------------------------------------------------------
// Target Type
// ---------------------------------------------------------------------------

export enum TargetType {
  URL = "url",
  Domain = "domain",
  IP = "ip",
  CIDR = "cidr",
  Repository = "repository",
  SmartContract = "smart_contract",
}

export const TargetTypeSchema = z.nativeEnum(TargetType);

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

export enum AuthenticationType {
  None = "none",
  Basic = "basic",
  Bearer = "bearer",
  Cookie = "cookie",
  OAuth = "oauth",
  APIKey = "api_key",
  Custom = "custom",
}

export const AuthenticationTypeSchema = z.nativeEnum(AuthenticationType);

/** Credentials for basic HTTP authentication. */
export interface BasicCredentials {
  username: string;
  password: string;
}

export const BasicCredentialsSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

/** Credentials for bearer token authentication. */
export interface BearerCredentials {
  token: string;
}

export const BearerCredentialsSchema = z.object({
  token: z.string().min(1),
});

/** Credentials for cookie-based authentication. */
export interface CookieCredentials {
  /** Cookie header value, e.g. "session=abc123; csrf=xyz". */
  cookieString: string;
}

export const CookieCredentialsSchema = z.object({
  cookieString: z.string().min(1),
});

/** Credentials for OAuth 2.0 authentication. */
export interface OAuthCredentials {
  clientId: string;
  clientSecret: string;
  tokenUrl: string;
  scopes?: string[];
  /** Pre-fetched access token (if available, skips token exchange). */
  accessToken?: string;
  refreshToken?: string;
}

export const OAuthCredentialsSchema = z.object({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  tokenUrl: z.string().url(),
  scopes: z.array(z.string()).optional(),
  accessToken: z.string().optional(),
  refreshToken: z.string().optional(),
});

/** Credentials for API key authentication. */
export interface APIKeyCredentials {
  /** Header name or query parameter name where the key is sent. */
  keyName: string;
  keyValue: string;
  /** Where to send the key: header, query string, or cookie. */
  in: "header" | "query" | "cookie";
}

export const APIKeyCredentialsSchema = z.object({
  keyName: z.string().min(1),
  keyValue: z.string().min(1),
  in: z.enum(["header", "query", "cookie"]),
});

/** Credentials for custom authentication flows. */
export interface CustomCredentials {
  /** Arbitrary key-value pairs for custom auth. */
  parameters: Record<string, string>;
  /** Optional description of how to use these credentials. */
  description?: string;
}

export const CustomCredentialsSchema = z.object({
  parameters: z.record(z.string()),
  description: z.string().optional(),
});

/**
 * Discriminated union for authentication configuration.
 * The `type` field determines which credentials shape is used.
 */
export type Authentication =
  | { type: AuthenticationType.None; credentials?: never }
  | { type: AuthenticationType.Basic; credentials: BasicCredentials }
  | { type: AuthenticationType.Bearer; credentials: BearerCredentials }
  | { type: AuthenticationType.Cookie; credentials: CookieCredentials }
  | { type: AuthenticationType.OAuth; credentials: OAuthCredentials }
  | { type: AuthenticationType.APIKey; credentials: APIKeyCredentials }
  | { type: AuthenticationType.Custom; credentials: CustomCredentials };

export const AuthenticationSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal(AuthenticationType.None),
  }),
  z.object({
    type: z.literal(AuthenticationType.Basic),
    credentials: BasicCredentialsSchema,
  }),
  z.object({
    type: z.literal(AuthenticationType.Bearer),
    credentials: BearerCredentialsSchema,
  }),
  z.object({
    type: z.literal(AuthenticationType.Cookie),
    credentials: CookieCredentialsSchema,
  }),
  z.object({
    type: z.literal(AuthenticationType.OAuth),
    credentials: OAuthCredentialsSchema,
  }),
  z.object({
    type: z.literal(AuthenticationType.APIKey),
    credentials: APIKeyCredentialsSchema,
  }),
  z.object({
    type: z.literal(AuthenticationType.Custom),
    credentials: CustomCredentialsSchema,
  }),
]);

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/** Defines what is in-scope and out-of-scope for scanning. */
export interface Scope {
  /** Domains and/or path patterns that are authorized for testing. */
  inScope: ScopeEntry[];
  /** Domains and/or path patterns that must NOT be tested. */
  outOfScope: ScopeEntry[];
}

export interface ScopeEntry {
  /** The pattern (domain, URL prefix, path glob, CIDR). */
  pattern: string;
  /** Optional human-readable note explaining this scope rule. */
  note?: string;
}

export const ScopeEntrySchema = z.object({
  pattern: z.string().min(1),
  note: z.string().optional(),
});

export const ScopeSchema = z.object({
  inScope: z.array(ScopeEntrySchema).min(1),
  outOfScope: z.array(ScopeEntrySchema),
});

// ---------------------------------------------------------------------------
// Target Metadata
// ---------------------------------------------------------------------------

/** Metadata collected during reconnaissance or provided by the user. */
export interface TargetMetadata {
  /** Detected or declared technology stack. */
  technologies?: string[];
  /** Server header value. */
  server?: string;
  /** Detected frameworks (e.g. "Next.js 14", "Django 5.0"). */
  frameworks?: string[];
  /** Detected CDN or WAF. */
  waf?: string;
  /** DNS records of interest. */
  dnsRecords?: Record<string, string[]>;
  /** IP addresses resolved for this target. */
  resolvedIps?: string[];
  /** Open ports discovered during network scanning. */
  openPorts?: number[];
  /** TLS/SSL certificate information. */
  tlsCertificate?: {
    issuer: string;
    subject: string;
    validFrom: string;
    validTo: string;
    serialNumber: string;
  };
  /** Blockchain network for smart contract targets. */
  chain?: string;
  /** Contract address for smart contract targets. */
  contractAddress?: string;
  /** Arbitrary additional metadata. */
  extra?: Record<string, unknown>;
}

export const TargetMetadataSchema = z.object({
  technologies: z.array(z.string()).optional(),
  server: z.string().optional(),
  frameworks: z.array(z.string()).optional(),
  waf: z.string().optional(),
  dnsRecords: z.record(z.array(z.string())).optional(),
  resolvedIps: z.array(z.string().ip()).optional(),
  openPorts: z
    .array(z.number().int().min(1).max(65535))
    .optional(),
  tlsCertificate: z
    .object({
      issuer: z.string(),
      subject: z.string(),
      validFrom: z.string().datetime(),
      validTo: z.string().datetime(),
      serialNumber: z.string(),
    })
    .optional(),
  chain: z.string().optional(),
  contractAddress: z.string().optional(),
  extra: z.record(z.unknown()).optional(),
});

// ---------------------------------------------------------------------------
// Target
// ---------------------------------------------------------------------------

export interface Target {
  /** Unique identifier (UUID v4). */
  id: string;
  /** Human-readable label for this target. */
  name: string;
  /** Classification of the target. */
  type: TargetType;
  /** The actual target value (URL, domain name, IP address, CIDR, repo URL, contract address). */
  value: string;
  /** Scanning scope rules. */
  scope?: Scope;
  /** User-defined tags for organization and filtering. */
  tags: string[];
  /** Authentication configuration for accessing the target. */
  authentication?: Authentication;
  /** Collected or declared metadata about the target. */
  metadata?: TargetMetadata;
  /** ISO-8601 timestamp. */
  createdAt: string;
  /** ISO-8601 timestamp. */
  updatedAt: string;
}

export const TargetSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(255),
  type: TargetTypeSchema,
  value: z.string().min(1),
  scope: ScopeSchema.optional(),
  tags: z.array(z.string()),
  authentication: AuthenticationSchema.optional(),
  metadata: TargetMetadataSchema.optional(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

// ---------------------------------------------------------------------------
// Inferred types from Zod
// ---------------------------------------------------------------------------

export type TargetInput = z.input<typeof TargetSchema>;
export type ScopeInput = z.input<typeof ScopeSchema>;
export type AuthenticationInput = z.input<typeof AuthenticationSchema>;
