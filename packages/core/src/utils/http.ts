export interface HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export interface HttpResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  responseTime: number;
}

export async function sendRequest(req: HttpRequest): Promise<HttpResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  const start = Date.now();

  try {
    const response = await fetch(req.url, {
      method: req.method,
      headers: req.headers,
      body: req.body,
      signal: controller.signal,
      redirect: "follow",
    });

    const body = await response.text();
    const responseTime = Date.now() - start;

    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });

    return {
      status: response.status,
      statusText: response.statusText,
      headers,
      body,
      responseTime,
    };
  } finally {
    clearTimeout(timeout);
  }
}

export function buildUrl(base: string, path: string, params?: Record<string, string>): string {
  const url = new URL(path, base);
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      url.searchParams.set(key, value);
    });
  }
  return url.toString();
}

export function parseHeaders(raw: string): Record<string, string> {
  const headers: Record<string, string> = {};
  raw.split("\n").forEach((line) => {
    const idx = line.indexOf(":");
    if (idx > 0) {
      headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
    }
  });
  return headers;
}
