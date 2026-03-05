// =============================================================================
// @vulnhunter/scanner - Technology Fingerprinting Module
// =============================================================================
// Identifies the technology stack of a target through:
//   1. HTTP header analysis (Server, X-Powered-By, X-Generator, etc.)
//   2. HTML meta tag detection
//   3. JavaScript library detection (React, Vue, Angular, jQuery, etc.)
//   4. Cookie analysis for framework identification
//   5. Known URL patterns (/wp-admin, /graphql, etc.)
//   6. Wappalyzer-style built-in technology database
// =============================================================================

import { randomBytes } from "crypto";
import type { ScanModule } from "../engine.js";
import type { Finding, Vulnerability } from "@vulnhunter/core";
import { Severity, VulnerabilityCategory } from "@vulnhunter/core";
import { createLogger } from "@vulnhunter/core";

const log = createLogger("recon:tech-detect");

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
// Technology database (Wappalyzer-style)
// ---------------------------------------------------------------------------

interface TechSignature {
  /** Technology name. */
  name: string;
  /** Category (e.g. "CMS", "Framework", "Server", "CDN"). */
  category: string;
  /** Website for reference. */
  website?: string;

  // Detection vectors (any match triggers detection)
  /** Match against HTTP response headers. Key is header name (lowercase). */
  headers?: Record<string, RegExp>;
  /** Match against cookie names. */
  cookies?: string[];
  /** Match against the raw HTML body. */
  html?: RegExp[];
  /** Match against <meta> tag name/property + content. */
  meta?: Record<string, RegExp>;
  /** Match against <script> src attributes. */
  scripts?: RegExp[];
  /** Match against URL paths that indicate the technology. */
  urlPatterns?: RegExp[];
  /** Regex to extract version from various signals. */
  versionPattern?: RegExp;
  /** Which signal to apply versionPattern against: "headers", "html", "scripts". */
  versionSource?: string;
  /** Specific header to extract version from. */
  versionHeader?: string;
}

const TECH_DATABASE: TechSignature[] = [
  // ---------------------------------------------------------------------------
  // Web Servers
  // ---------------------------------------------------------------------------
  {
    name: "Apache",
    category: "Web Server",
    website: "https://httpd.apache.org",
    headers: { server: /Apache\/?/i },
    versionPattern: /Apache\/([\d.]+)/i,
    versionSource: "headers",
    versionHeader: "server",
  },
  {
    name: "Nginx",
    category: "Web Server",
    website: "https://nginx.org",
    headers: { server: /nginx\/?/i },
    versionPattern: /nginx\/([\d.]+)/i,
    versionSource: "headers",
    versionHeader: "server",
  },
  {
    name: "Microsoft IIS",
    category: "Web Server",
    website: "https://www.iis.net",
    headers: { server: /Microsoft-IIS\/?/i },
    versionPattern: /Microsoft-IIS\/([\d.]+)/i,
    versionSource: "headers",
    versionHeader: "server",
  },
  {
    name: "LiteSpeed",
    category: "Web Server",
    website: "https://www.litespeedtech.com",
    headers: { server: /LiteSpeed/i },
  },
  {
    name: "Caddy",
    category: "Web Server",
    website: "https://caddyserver.com",
    headers: { server: /Caddy/i },
  },
  {
    name: "Envoy",
    category: "Web Server / Proxy",
    website: "https://www.envoyproxy.io",
    headers: { server: /envoy/i },
  },
  {
    name: "OpenResty",
    category: "Web Server",
    website: "https://openresty.org",
    headers: { server: /openresty/i },
  },

  // ---------------------------------------------------------------------------
  // Programming Languages / Runtimes
  // ---------------------------------------------------------------------------
  {
    name: "PHP",
    category: "Programming Language",
    website: "https://www.php.net",
    headers: { "x-powered-by": /PHP\/?/i },
    cookies: ["PHPSESSID"],
    versionPattern: /PHP\/([\d.]+)/i,
    versionSource: "headers",
    versionHeader: "x-powered-by",
  },
  {
    name: "ASP.NET",
    category: "Framework",
    website: "https://dotnet.microsoft.com/apps/aspnet",
    headers: { "x-powered-by": /ASP\.NET/i, "x-aspnet-version": /.+/ },
    cookies: ["ASP.NET_SessionId", ".AspNetCore.Session"],
    versionPattern: /X-AspNet-Version:\s*([\d.]+)/i,
  },
  {
    name: "Python",
    category: "Programming Language",
    website: "https://www.python.org",
    headers: { server: /Python\/?/i, "x-powered-by": /Python/i },
  },
  {
    name: "Node.js",
    category: "Runtime",
    website: "https://nodejs.org",
    headers: { "x-powered-by": /Express/i },
  },
  {
    name: "Java",
    category: "Programming Language",
    headers: {
      "x-powered-by": /Servlet|JSP|JSF/i,
      server: /Tomcat|Jetty|GlassFish|WildFly|JBoss/i,
    },
    cookies: ["JSESSIONID"],
  },
  {
    name: "Ruby",
    category: "Programming Language",
    website: "https://www.ruby-lang.org",
    headers: {
      "x-powered-by": /Phusion Passenger/i,
      server: /Passenger|Puma|Unicorn|Thin/i,
    },
    cookies: ["_session_id"],
  },
  {
    name: "Go",
    category: "Programming Language",
    website: "https://go.dev",
    headers: { server: /^Go$/i },
  },

  // ---------------------------------------------------------------------------
  // JavaScript Frameworks (Front-End)
  // ---------------------------------------------------------------------------
  {
    name: "React",
    category: "JavaScript Framework",
    website: "https://react.dev",
    html: [/data-reactroot/i, /data-reactid/i, /__NEXT_DATA__/],
    scripts: [/react(?:\.production\.min)?\.js/i, /react-dom/i],
  },
  {
    name: "Next.js",
    category: "JavaScript Framework",
    website: "https://nextjs.org",
    html: [/__NEXT_DATA__/, /\/_next\//],
    headers: { "x-powered-by": /Next\.js/i },
    scripts: [/\/_next\/static/],
    meta: { generator: /Next\.js/i },
  },
  {
    name: "Vue.js",
    category: "JavaScript Framework",
    website: "https://vuejs.org",
    html: [/data-v-[a-f0-9]+/i, /id="__nuxt"/i, /v-cloak/i],
    scripts: [/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js/i],
  },
  {
    name: "Nuxt.js",
    category: "JavaScript Framework",
    website: "https://nuxt.com",
    html: [/id="__nuxt"/, /__NUXT__/],
    headers: { "x-powered-by": /Nuxt/i },
    scripts: [/\/_nuxt\//],
  },
  {
    name: "Angular",
    category: "JavaScript Framework",
    website: "https://angular.dev",
    html: [/ng-version=/i, /ng-app=/i, /\bng-[a-z]/i],
    scripts: [/angular(?:\.min)?\.js/i, /zone(?:\.min)?\.js/i],
  },
  {
    name: "Svelte",
    category: "JavaScript Framework",
    website: "https://svelte.dev",
    html: [/svelte-[a-z0-9]+/i, /__svelte/],
    scripts: [/svelte/i],
  },
  {
    name: "SvelteKit",
    category: "JavaScript Framework",
    website: "https://kit.svelte.dev",
    html: [/__sveltekit/],
    scripts: [/\/_app\/immutable\//],
  },
  {
    name: "Remix",
    category: "JavaScript Framework",
    website: "https://remix.run",
    html: [/__remixContext/],
    scripts: [/remix/i],
  },
  {
    name: "Astro",
    category: "JavaScript Framework",
    website: "https://astro.build",
    html: [/astro-island/i, /astro-slot/i],
    meta: { generator: /Astro/i },
  },
  {
    name: "Gatsby",
    category: "JavaScript Framework",
    website: "https://www.gatsbyjs.com",
    html: [/___gatsby/i, /gatsby-/i],
    meta: { generator: /Gatsby/i },
  },
  {
    name: "jQuery",
    category: "JavaScript Library",
    website: "https://jquery.com",
    scripts: [/jquery[.-]?([\d.]+)?(?:\.min)?\.js/i],
    html: [/jQuery\s*v?([\d.]+)/i],
    versionPattern: /jquery[.-]?([\d.]+)/i,
    versionSource: "scripts",
  },
  {
    name: "Bootstrap",
    category: "CSS Framework",
    website: "https://getbootstrap.com",
    html: [/bootstrap(?:\.min)?\.css/i, /class="[^"]*\bcontainer\b[^"]*\brow\b/i],
    scripts: [/bootstrap(?:\.bundle)?(?:\.min)?\.js/i],
  },
  {
    name: "Tailwind CSS",
    category: "CSS Framework",
    website: "https://tailwindcss.com",
    html: [/class="[^"]*\b(?:flex|grid|bg-|text-|p-|m-|w-|h-)\b/i],
  },
  {
    name: "Alpine.js",
    category: "JavaScript Framework",
    website: "https://alpinejs.dev",
    html: [/x-data=/i, /x-bind:/i, /x-on:/i],
    scripts: [/alpine(?:\.min)?\.js/i],
  },
  {
    name: "HTMX",
    category: "JavaScript Library",
    website: "https://htmx.org",
    html: [/hx-get=/i, /hx-post=/i, /hx-trigger=/i],
    scripts: [/htmx(?:\.min)?\.js/i],
  },

  // ---------------------------------------------------------------------------
  // CMS
  // ---------------------------------------------------------------------------
  {
    name: "WordPress",
    category: "CMS",
    website: "https://wordpress.org",
    html: [/wp-content\//i, /wp-includes\//i, /wp-json/i],
    meta: { generator: /WordPress\s*([\d.]+)?/i },
    cookies: ["wordpress_logged_in", "wp-settings"],
    urlPatterns: [/\/wp-admin/i, /\/wp-login\.php/i, /\/xmlrpc\.php/i],
    versionPattern: /WordPress\s*([\d.]+)/i,
    versionSource: "html",
  },
  {
    name: "Drupal",
    category: "CMS",
    website: "https://www.drupal.org",
    html: [/Drupal\.settings/i, /drupal\.js/i, /sites\/default\/files/i],
    meta: { generator: /Drupal/i },
    headers: { "x-generator": /Drupal/i, "x-drupal-cache": /.+/ },
    urlPatterns: [/\/node\/\d+/i, /\/admin\/config/i],
  },
  {
    name: "Joomla",
    category: "CMS",
    website: "https://www.joomla.org",
    html: [/\/media\/jui\/js/i, /\/media\/system\/js/i],
    meta: { generator: /Joomla/i },
    urlPatterns: [/\/administrator\//i],
  },
  {
    name: "Shopify",
    category: "E-Commerce",
    website: "https://www.shopify.com",
    html: [/cdn\.shopify\.com/i, /Shopify\.theme/i],
    headers: { "x-shopify-stage": /.+/ },
    cookies: ["_shopify_s", "_shopify_y"],
  },
  {
    name: "Magento",
    category: "E-Commerce",
    website: "https://business.adobe.com/products/magento/magento-commerce.html",
    html: [/mage\/cookies/i, /Mage\.Cookies/i, /\/static\/version/i],
    cookies: ["PHPSESSID", "frontend"],
    urlPatterns: [/\/customer\/account\/login/i, /\/checkout\/cart/i],
  },
  {
    name: "Wix",
    category: "CMS / Website Builder",
    website: "https://www.wix.com",
    html: [/wixcode-/i, /static\.wixstatic\.com/i, /_wix_browser_sess/i],
    headers: { "x-wix-request-id": /.+/ },
  },
  {
    name: "Squarespace",
    category: "CMS / Website Builder",
    website: "https://www.squarespace.com",
    html: [/squarespace/i, /sqsp/i],
    meta: { generator: /Squarespace/i },
  },
  {
    name: "Ghost",
    category: "CMS",
    website: "https://ghost.org",
    html: [/ghost-/i],
    meta: { generator: /Ghost/i },
    headers: { "x-powered-by": /Express/i },
  },
  {
    name: "Hugo",
    category: "Static Site Generator",
    website: "https://gohugo.io",
    meta: { generator: /Hugo/i },
  },

  // ---------------------------------------------------------------------------
  // Backend Frameworks
  // ---------------------------------------------------------------------------
  {
    name: "Django",
    category: "Web Framework",
    website: "https://www.djangoproject.com",
    cookies: ["csrftoken", "sessionid"],
    html: [/csrfmiddlewaretoken/i],
    headers: { "x-frame-options": /DENY/i },
  },
  {
    name: "Flask",
    category: "Web Framework",
    website: "https://flask.palletsprojects.com",
    headers: { server: /Werkzeug/i },
  },
  {
    name: "FastAPI",
    category: "Web Framework",
    website: "https://fastapi.tiangolo.com",
    urlPatterns: [/\/docs$/i, /\/openapi\.json$/i, /\/redoc$/i],
  },
  {
    name: "Express.js",
    category: "Web Framework",
    website: "https://expressjs.com",
    headers: { "x-powered-by": /^Express$/i },
  },
  {
    name: "Ruby on Rails",
    category: "Web Framework",
    website: "https://rubyonrails.org",
    headers: { "x-powered-by": /Phusion Passenger/i },
    cookies: ["_rails_session", "_session_id"],
    html: [/csrf-token/i, /authenticity_token/i],
    meta: { "csrf-token": /.+/ },
  },
  {
    name: "Laravel",
    category: "Web Framework",
    website: "https://laravel.com",
    cookies: ["laravel_session", "XSRF-TOKEN"],
    html: [/laravel/i],
  },
  {
    name: "Spring",
    category: "Web Framework",
    website: "https://spring.io",
    headers: { "x-application-context": /.+/ },
    cookies: ["JSESSIONID"],
    urlPatterns: [/\/actuator/i, /\/actuator\/health/i],
  },

  // ---------------------------------------------------------------------------
  // CDN / WAF / Proxy
  // ---------------------------------------------------------------------------
  {
    name: "Cloudflare",
    category: "CDN / WAF",
    website: "https://www.cloudflare.com",
    headers: { server: /cloudflare/i, "cf-ray": /.+/, "cf-cache-status": /.+/ },
    cookies: ["__cfduid", "cf_clearance", "__cf_bm"],
  },
  {
    name: "AWS CloudFront",
    category: "CDN",
    website: "https://aws.amazon.com/cloudfront/",
    headers: {
      via: /CloudFront/i,
      "x-amz-cf-id": /.+/,
      "x-amz-cf-pop": /.+/,
    },
  },
  {
    name: "Akamai",
    category: "CDN",
    website: "https://www.akamai.com",
    headers: {
      "x-akamai-transformed": /.+/,
      server: /AkamaiGHost/i,
    },
  },
  {
    name: "Fastly",
    category: "CDN",
    website: "https://www.fastly.com",
    headers: {
      via: /varnish/i,
      "x-served-by": /cache-/i,
      "x-fastly-request-id": /.+/,
    },
  },
  {
    name: "Vercel",
    category: "PaaS / CDN",
    website: "https://vercel.com",
    headers: {
      server: /Vercel/i,
      "x-vercel-id": /.+/,
      "x-vercel-cache": /.+/,
    },
  },
  {
    name: "Netlify",
    category: "PaaS / CDN",
    website: "https://www.netlify.com",
    headers: { server: /Netlify/i, "x-nf-request-id": /.+/ },
  },
  {
    name: "AWS ALB/ELB",
    category: "Load Balancer",
    website: "https://aws.amazon.com/elasticloadbalancing/",
    headers: { server: /awselb/i },
    cookies: ["AWSALB", "AWSALBCORS"],
  },
  {
    name: "Sucuri WAF",
    category: "WAF",
    website: "https://sucuri.net",
    headers: {
      server: /Sucuri/i,
      "x-sucuri-id": /.+/,
    },
  },
  {
    name: "Imperva/Incapsula",
    category: "WAF",
    website: "https://www.imperva.com",
    headers: { "x-iinfo": /.+/ },
    cookies: ["incap_ses", "visid_incap"],
  },

  // ---------------------------------------------------------------------------
  // Analytics / Tag Managers
  // ---------------------------------------------------------------------------
  {
    name: "Google Analytics",
    category: "Analytics",
    website: "https://analytics.google.com",
    html: [/google-analytics\.com\/analytics\.js/i, /gtag\/js/i, /UA-\d+-\d+/],
    scripts: [/google-analytics\.com/i, /googletagmanager\.com/i],
  },
  {
    name: "Google Tag Manager",
    category: "Tag Manager",
    website: "https://tagmanager.google.com",
    html: [/googletagmanager\.com\/gtm\.js/i, /GTM-[A-Z0-9]+/],
  },
  {
    name: "Facebook Pixel",
    category: "Analytics",
    html: [/connect\.facebook\.net\/.*\/fbevents\.js/i, /fbq\s*\(/i],
  },
  {
    name: "Hotjar",
    category: "Analytics",
    website: "https://www.hotjar.com",
    html: [/static\.hotjar\.com/i],
    scripts: [/hotjar\.com/i],
  },

  // ---------------------------------------------------------------------------
  // APIs / Protocols
  // ---------------------------------------------------------------------------
  {
    name: "GraphQL",
    category: "API",
    urlPatterns: [/\/graphql\/?$/i, /\/gql\/?$/i],
    html: [/__APOLLO_STATE__/i, /graphql/i],
  },
  {
    name: "REST API",
    category: "API",
    urlPatterns: [/\/api\/v\d+\//i, /\/api\//i],
    headers: { "content-type": /application\/json/i },
  },
  {
    name: "WebSocket",
    category: "Protocol",
    headers: { upgrade: /websocket/i },
    html: [/new\s+WebSocket\s*\(/i, /wss?:\/\//i],
  },

  // ---------------------------------------------------------------------------
  // Security Headers Detection
  // ---------------------------------------------------------------------------
  {
    name: "Content Security Policy",
    category: "Security Header",
    headers: { "content-security-policy": /.+/ },
  },
  {
    name: "Strict-Transport-Security",
    category: "Security Header",
    headers: { "strict-transport-security": /.+/ },
  },

  // ---------------------------------------------------------------------------
  // Miscellaneous
  // ---------------------------------------------------------------------------
  {
    name: "reCAPTCHA",
    category: "Security",
    website: "https://www.google.com/recaptcha/",
    html: [/google\.com\/recaptcha/i, /g-recaptcha/i],
    scripts: [/recaptcha/i],
  },
  {
    name: "hCaptcha",
    category: "Security",
    website: "https://www.hcaptcha.com",
    html: [/hcaptcha\.com/i, /h-captcha/i],
  },
  {
    name: "Sentry",
    category: "Error Tracking",
    website: "https://sentry.io",
    html: [/sentry\.io/i, /Sentry\.init/i],
    scripts: [/sentry/i, /browser\.sentry-cdn\.com/i],
  },
  {
    name: "Stripe",
    category: "Payment",
    website: "https://stripe.com",
    html: [/js\.stripe\.com/i, /Stripe\s*\(/i],
    scripts: [/stripe\.com/i],
  },
  {
    name: "PayPal",
    category: "Payment",
    website: "https://www.paypal.com",
    html: [/paypal\.com\/sdk/i, /paypal-button/i],
    scripts: [/paypalobjects\.com/i],
  },
];

// ---------------------------------------------------------------------------
// URL probes: paths to check for technology indicators
// ---------------------------------------------------------------------------
const URL_PROBES: Array<{ path: string; technology: string; category: string }> = [
  { path: "/wp-admin/", technology: "WordPress", category: "CMS" },
  { path: "/wp-login.php", technology: "WordPress", category: "CMS" },
  { path: "/wp-json/wp/v2/", technology: "WordPress REST API", category: "CMS" },
  { path: "/administrator/", technology: "Joomla", category: "CMS" },
  { path: "/user/login", technology: "Drupal", category: "CMS" },
  { path: "/graphql", technology: "GraphQL", category: "API" },
  { path: "/graphiql", technology: "GraphQL IDE", category: "API" },
  { path: "/.env", technology: "Environment File Exposed", category: "Misconfiguration" },
  { path: "/actuator/health", technology: "Spring Boot Actuator", category: "Web Framework" },
  { path: "/api/swagger.json", technology: "Swagger/OpenAPI", category: "API" },
  { path: "/swagger-ui.html", technology: "Swagger UI", category: "API" },
  { path: "/docs", technology: "FastAPI Docs", category: "API" },
  { path: "/openapi.json", technology: "OpenAPI Spec", category: "API" },
  { path: "/redoc", technology: "ReDoc", category: "API" },
  { path: "/elmah.axd", technology: "ELMAH (.NET)", category: "Error Tracking" },
  { path: "/server-status", technology: "Apache Status", category: "Web Server" },
  { path: "/nginx_status", technology: "Nginx Status", category: "Web Server" },
  { path: "/.git/HEAD", technology: "Git Repository Exposed", category: "Misconfiguration" },
  { path: "/.svn/entries", technology: "SVN Repository Exposed", category: "Misconfiguration" },
  { path: "/robots.txt", technology: "Robots.txt", category: "SEO" },
  { path: "/sitemap.xml", technology: "Sitemap XML", category: "SEO" },
  { path: "/crossdomain.xml", technology: "Flash Crossdomain Policy", category: "Security" },
  { path: "/.well-known/security.txt", technology: "Security.txt", category: "Security" },
  { path: "/phpmyadmin/", technology: "phpMyAdmin", category: "Database Tool" },
  { path: "/adminer.php", technology: "Adminer", category: "Database Tool" },
];

// ---------------------------------------------------------------------------
// TechDetector
// ---------------------------------------------------------------------------

export class TechDetector implements ScanModule {
  readonly name = "recon:tech-detect";

  private timeoutMs = 15000;
  private userAgent = "VulnHunter/1.0 (Security Scanner)";
  private customHeaders: Record<string, string> = {};

  async init(
    _target: string,
    options: Record<string, unknown>,
  ): Promise<void> {
    if (typeof options.requestTimeoutMs === "number") {
      this.timeoutMs = options.requestTimeoutMs;
    }
    if (typeof options.userAgent === "string") {
      this.userAgent = options.userAgent;
    }
    if (
      options.customHeaders &&
      typeof options.customHeaders === "object"
    ) {
      this.customHeaders = options.customHeaders as Record<string, string>;
    }

    log.info("TechDetector initialized");
  }

  async *execute(
    target: string,
    _options: Record<string, unknown>,
  ): AsyncGenerator<Finding> {
    const baseUrl = this.normalizeUrl(target);
    log.info({ baseUrl }, "Starting technology detection");

    // Deduplicate detections
    const detected = new Map<string, { version: string; evidence: string[] }>();

    // --- Phase 1: Fetch the main page and analyze headers + body ---
    const mainPage = await this.fetchPage(baseUrl);
    if (mainPage) {
      this.analyzeHeaders(mainPage.headers, detected);
      this.analyzeCookies(mainPage.setCookies, detected);
      this.analyzeHtml(mainPage.body, detected);
      this.analyzeScripts(mainPage.body, detected);
      this.analyzeMetaTags(mainPage.body, detected);
    }

    // --- Phase 2: URL probes ---
    log.info({ baseUrl, probeCount: URL_PROBES.length }, "Running URL probes");
    const probeResults = await this.runUrlProbes(baseUrl);
    for (const probe of probeResults) {
      const key = probe.technology;
      if (!detected.has(key)) {
        detected.set(key, {
          version: "",
          evidence: [`URL probe: ${probe.path} returned ${probe.status}`],
        });
      } else {
        detected.get(key)!.evidence.push(
          `URL probe: ${probe.path} returned ${probe.status}`,
        );
      }
    }

    log.info(
      { baseUrl, technologiesFound: detected.size },
      "Technology detection complete",
    );

    // Yield findings
    for (const [techName, info] of detected) {
      yield this.createFinding(
        baseUrl,
        techName,
        info.version,
        info.evidence,
      );
    }
  }

  async cleanup(): Promise<void> {
    log.info("TechDetector cleanup complete");
  }

  // -------------------------------------------------------------------------
  // HTTP Fetching
  // -------------------------------------------------------------------------

  private async fetchPage(
    url: string,
  ): Promise<{
    body: string;
    headers: Record<string, string>;
    setCookies: string[];
    status: number;
  } | null> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        this.timeoutMs,
      );

      const response = await fetch(url, {
        method: "GET",
        headers: {
          "User-Agent": this.userAgent,
          Accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
          ...this.customHeaders,
        },
        signal: controller.signal,
        redirect: "follow",
      });

      clearTimeout(timeout);

      const body = await response.text();

      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });

      // Extract Set-Cookie headers
      const setCookies: string[] = [];
      const rawCookies = response.headers.getSetCookie?.();
      if (rawCookies) {
        setCookies.push(...rawCookies);
      } else {
        // Fallback: parse from headers
        const cookieHeader = response.headers.get("set-cookie");
        if (cookieHeader) {
          setCookies.push(cookieHeader);
        }
      }

      return { body, headers, setCookies, status: response.status };
    } catch (error) {
      log.warn(
        {
          url,
          error:
            error instanceof Error ? error.message : String(error),
        },
        "Failed to fetch page",
      );
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Header Analysis
  // -------------------------------------------------------------------------

  private analyzeHeaders(
    headers: Record<string, string>,
    detected: Map<string, { version: string; evidence: string[] }>,
  ): void {
    for (const tech of TECH_DATABASE) {
      if (!tech.headers) continue;

      for (const [headerName, pattern] of Object.entries(tech.headers)) {
        const headerValue = headers[headerName];
        if (headerValue && pattern.test(headerValue)) {
          let version = "";
          if (
            tech.versionPattern &&
            tech.versionSource === "headers" &&
            tech.versionHeader
          ) {
            const versionValue = headers[tech.versionHeader];
            if (versionValue) {
              const match = versionValue.match(tech.versionPattern);
              if (match && match[1]) {
                version = match[1];
              }
            }
          }

          this.addDetection(
            detected,
            tech.name,
            version,
            `Header "${headerName}: ${headerValue}"`,
          );
          break; // Only need one header match per tech
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Cookie Analysis
  // -------------------------------------------------------------------------

  private analyzeCookies(
    setCookies: string[],
    detected: Map<string, { version: string; evidence: string[] }>,
  ): void {
    const cookieNames = setCookies.map((c) => {
      const eqIdx = c.indexOf("=");
      return eqIdx > 0 ? c.slice(0, eqIdx).trim() : c.trim();
    });

    for (const tech of TECH_DATABASE) {
      if (!tech.cookies) continue;

      for (const expectedCookie of tech.cookies) {
        if (
          cookieNames.some(
            (name) =>
              name.toLowerCase() === expectedCookie.toLowerCase() ||
              name.toLowerCase().startsWith(expectedCookie.toLowerCase()),
          )
        ) {
          this.addDetection(
            detected,
            tech.name,
            "",
            `Cookie "${expectedCookie}" detected`,
          );
          break;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // HTML Analysis
  // -------------------------------------------------------------------------

  private analyzeHtml(
    body: string,
    detected: Map<string, { version: string; evidence: string[] }>,
  ): void {
    for (const tech of TECH_DATABASE) {
      if (!tech.html) continue;

      for (const pattern of tech.html) {
        const match = body.match(pattern);
        if (match) {
          let version = "";
          if (tech.versionPattern && tech.versionSource === "html") {
            const vMatch = body.match(tech.versionPattern);
            if (vMatch && vMatch[1]) {
              version = vMatch[1];
            }
          }

          this.addDetection(
            detected,
            tech.name,
            version,
            `HTML pattern: ${pattern.source.slice(0, 60)}`,
          );
          break;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Script Analysis
  // -------------------------------------------------------------------------

  private analyzeScripts(
    body: string,
    detected: Map<string, { version: string; evidence: string[] }>,
  ): void {
    // Extract all <script src="..."> values
    const scriptSrcPattern = /<script[^>]+src=["']([^"']+)["']/gi;
    const scriptSrcs: string[] = [];
    let scriptMatch: RegExpExecArray | null;
    while ((scriptMatch = scriptSrcPattern.exec(body)) !== null) {
      scriptSrcs.push(scriptMatch[1]);
    }

    for (const tech of TECH_DATABASE) {
      if (!tech.scripts) continue;

      for (const pattern of tech.scripts) {
        const matchingSrc = scriptSrcs.find((src) => pattern.test(src));
        if (matchingSrc) {
          let version = "";
          if (tech.versionPattern && tech.versionSource === "scripts") {
            const vMatch = matchingSrc.match(tech.versionPattern);
            if (vMatch && vMatch[1]) {
              version = vMatch[1];
            }
          }

          this.addDetection(
            detected,
            tech.name,
            version,
            `Script src: ${matchingSrc.slice(0, 80)}`,
          );
          break;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Meta Tag Analysis
  // -------------------------------------------------------------------------

  private analyzeMetaTags(
    body: string,
    detected: Map<string, { version: string; evidence: string[] }>,
  ): void {
    // Extract <meta name="..." content="..."> and <meta property="..." content="...">
    const metaPattern =
      /<meta\s+(?:name|property)=["']([^"']+)["']\s+content=["']([^"']+)["']/gi;
    const metas = new Map<string, string>();
    let metaMatch: RegExpExecArray | null;
    while ((metaMatch = metaPattern.exec(body)) !== null) {
      metas.set(metaMatch[1].toLowerCase(), metaMatch[2]);
    }

    // Also check content-first format: <meta content="..." name="...">
    const metaPattern2 =
      /<meta\s+content=["']([^"']+)["']\s+(?:name|property)=["']([^"']+)["']/gi;
    while ((metaMatch = metaPattern2.exec(body)) !== null) {
      metas.set(metaMatch[2].toLowerCase(), metaMatch[1]);
    }

    for (const tech of TECH_DATABASE) {
      if (!tech.meta) continue;

      for (const [metaName, pattern] of Object.entries(tech.meta)) {
        const content = metas.get(metaName.toLowerCase());
        if (content && pattern.test(content)) {
          let version = "";
          if (tech.versionPattern) {
            const vMatch = content.match(tech.versionPattern);
            if (vMatch && vMatch[1]) {
              version = vMatch[1];
            }
          }

          this.addDetection(
            detected,
            tech.name,
            version,
            `Meta tag "${metaName}": "${content}"`,
          );
          break;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // URL Probes
  // -------------------------------------------------------------------------

  private async runUrlProbes(
    baseUrl: string,
  ): Promise<
    Array<{
      path: string;
      technology: string;
      category: string;
      status: number;
    }>
  > {
    const results: Array<{
      path: string;
      technology: string;
      category: string;
      status: number;
    }> = [];

    // Batch probes in groups of 10
    for (let i = 0; i < URL_PROBES.length; i += 10) {
      const batch = URL_PROBES.slice(i, i + 10);
      const batchResults = await Promise.allSettled(
        batch.map(async (probe) => {
          const url = new URL(probe.path, baseUrl).toString();
          try {
            const controller = new AbortController();
            const timeout = setTimeout(
              () => controller.abort(),
              this.timeoutMs,
            );

            const response = await fetch(url, {
              method: "HEAD",
              headers: {
                "User-Agent": this.userAgent,
                ...this.customHeaders,
              },
              signal: controller.signal,
              redirect: "follow",
            });

            clearTimeout(timeout);

            // Consider 2xx and 3xx as "found"
            if (response.status >= 200 && response.status < 400) {
              return {
                path: probe.path,
                technology: probe.technology,
                category: probe.category,
                status: response.status,
              };
            }
            return null;
          } catch {
            return null;
          }
        }),
      );

      for (const result of batchResults) {
        if (result.status === "fulfilled" && result.value !== null) {
          results.push(result.value);
        }
      }
    }

    return results;
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private addDetection(
    detected: Map<string, { version: string; evidence: string[] }>,
    techName: string,
    version: string,
    evidence: string,
  ): void {
    const existing = detected.get(techName);
    if (existing) {
      existing.evidence.push(evidence);
      if (version && !existing.version) {
        existing.version = version;
      }
    } else {
      detected.set(techName, { version, evidence: [evidence] });
    }
  }

  private normalizeUrl(target: string): string {
    if (!target.includes("://")) {
      return `https://${target}`;
    }
    return target;
  }

  private createFinding(
    baseUrl: string,
    techName: string,
    version: string,
    evidence: string[],
  ): Finding {
    const now = new Date().toISOString();
    const displayName = version ? `${techName} ${version}` : techName;

    // Look up the category from the database
    const techEntry = TECH_DATABASE.find((t) => t.name === techName);
    const techCategory = techEntry?.category ?? "Unknown";

    // Misconfigurations and exposed tools get higher severity
    const isMisconfig =
      techName.includes("Exposed") || techName.includes("Misconfiguration");
    const isAdminTool =
      techName.includes("phpMyAdmin") || techName.includes("Adminer");

    let severity = Severity.Info;
    if (isMisconfig) severity = Severity.Medium;
    if (isAdminTool) severity = Severity.High;

    const vulnerability: Vulnerability = {
      id: uuid(),
      title: `Technology detected: ${displayName}`,
      description:
        `The technology "${displayName}" (category: ${techCategory}) was identified on ${baseUrl}. ` +
        `Detection was based on: ${evidence.join("; ")}. ` +
        `Knowing the technology stack helps an attacker identify relevant CVEs and attack vectors.`,
      severity,
      category: VulnerabilityCategory.InformationDisclosure,
      cvssScore: isMisconfig ? 5.3 : isAdminTool ? 6.5 : 0.0,
      target: baseUrl,
      endpoint: baseUrl,
      evidence: {
        description: `Detected ${displayName} via ${evidence.length} signal(s)`,
        extra: {
          technology: techName,
          version,
          category: techCategory,
          website: techEntry?.website ?? "",
          signals: evidence,
        },
      },
      remediation:
        isMisconfig || isAdminTool
          ? `Remove or restrict access to sensitive resources. Ensure admin panels and configuration files are not publicly accessible.`
          : `Consider removing unnecessary technology fingerprints from HTTP headers (Server, X-Powered-By). ` +
            `Keep ${techName} updated to the latest version to mitigate known vulnerabilities.`,
      references: [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
      ],
      confirmed: true,
      falsePositive: false,
      discoveredAt: now,
    };

    return {
      vulnerability,
      module: this.name,
      confidence: evidence.length >= 3 ? 95 : evidence.length >= 2 ? 85 : 70,
      timestamp: now,
      rawData: {
        technology: techName,
        version,
        category: techCategory,
        evidence,
      },
    };
  }
}
