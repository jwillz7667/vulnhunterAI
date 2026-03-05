import { createLogger } from "./logger.js";

const log = createLogger("retry");

export interface RetryOptions {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  backoffFactor: number;
  retryableErrors?: string[];
}

const DEFAULT_OPTIONS: RetryOptions = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
  backoffFactor: 2,
};

export async function withRetry<T>(
  fn: () => Promise<T>,
  options: Partial<RetryOptions> = {}
): Promise<T> {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt === opts.maxRetries) break;

      if (
        opts.retryableErrors &&
        !opts.retryableErrors.some((e) => lastError!.message.includes(e))
      ) {
        throw lastError;
      }

      const delay = Math.min(
        opts.baseDelayMs * Math.pow(opts.backoffFactor, attempt),
        opts.maxDelayMs
      );
      const jitter = delay * 0.1 * Math.random();

      log.warn(
        { attempt: attempt + 1, maxRetries: opts.maxRetries, delay: delay + jitter },
        `Retry attempt ${attempt + 1}/${opts.maxRetries}`
      );

      await new Promise((resolve) => setTimeout(resolve, delay + jitter));
    }
  }

  throw lastError;
}
