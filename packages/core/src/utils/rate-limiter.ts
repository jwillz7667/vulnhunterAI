export class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private readonly maxTokens: number;
  private readonly refillRate: number;

  constructor(requestsPerSecond: number) {
    this.maxTokens = requestsPerSecond;
    this.tokens = requestsPerSecond;
    this.refillRate = requestsPerSecond;
    this.lastRefill = Date.now();
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.maxTokens, this.tokens + elapsed * this.refillRate);
    this.lastRefill = now;
  }

  async acquire(): Promise<void> {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return;
    }
    const waitTime = ((1 - this.tokens) / this.refillRate) * 1000;
    await new Promise((resolve) => setTimeout(resolve, waitTime));
    this.tokens = 0;
    this.lastRefill = Date.now();
  }

  get availableTokens(): number {
    this.refill();
    return Math.floor(this.tokens);
  }
}
