// =============================================================================
// @vulnhunter/cli - Progress Display
// =============================================================================
// Provides a ScanProgressDisplay class that wraps ora spinners with elapsed
// time tracking, request counters, and findings count. Designed for long-
// running scan operations where the user needs real-time feedback.
// =============================================================================

import type { ScanProgress } from "@vulnhunter/core";

/**
 * Dynamically imports ESM-only dependencies (chalk, ora).
 * Commander.js and cli-table3 are CJS-compatible, but chalk v5+ and ora v8+
 * ship as pure ESM. We use dynamic imports to avoid top-level await issues
 * in mixed-module monorepos.
 */
async function loadDeps() {
  const [{ default: chalk }, { default: ora }] = await Promise.all([
    import("chalk"),
    import("ora"),
  ]);
  return { chalk, ora };
}

/**
 * Formats milliseconds into a human-readable elapsed time string.
 * Examples: "0s", "45s", "2m 15s", "1h 3m 22s"
 */
function formatElapsed(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }
  return `${seconds}s`;
}

/**
 * Renders a compact progress bar using block characters.
 * @param percent - Value between 0 and 100
 * @param width  - Character width of the bar (default 20)
 */
function renderProgressBar(percent: number, width = 20): string {
  const filled = Math.round((percent / 100) * width);
  const empty = width - filled;
  const bar = "\u2588".repeat(filled) + "\u2591".repeat(empty);
  return `[${bar}] ${percent.toFixed(0)}%`;
}

export interface ProgressState {
  phase: string;
  module: string;
  progressPercent: number;
  message: string;
  findingsCount: number;
  endpointsTested: number;
  requestsSent: number;
}

/**
 * ScanProgressDisplay manages a terminal spinner with rich status information.
 *
 * Usage:
 *   const display = new ScanProgressDisplay();
 *   await display.start("Initializing scan...");
 *   await display.update({ phase: "recon", module: "subdomain", ... });
 *   await display.complete();
 */
export class ScanProgressDisplay {
  private spinner: any = null;
  private chalk: any = null;
  private startTime: number = 0;
  private lastState: ProgressState | null = null;
  private intervalHandle: ReturnType<typeof setInterval> | null = null;

  /**
   * Starts the spinner with an initial message.
   * Internally loads ESM dependencies on first call.
   */
  async start(initialMessage = "Starting scan..."): Promise<void> {
    const { chalk, ora } = await loadDeps();
    this.chalk = chalk;
    this.startTime = Date.now();

    this.spinner = ora({
      text: initialMessage,
      color: "cyan",
      spinner: "dots12",
    }).start();

    // Refresh the elapsed time display every second even without new events
    this.intervalHandle = setInterval(() => {
      if (this.lastState && this.spinner?.isSpinning) {
        this.renderState(this.lastState);
      }
    }, 1000);
  }

  /**
   * Updates the display with new progress data.
   * Accepts either the full ScanProgress type from core or a partial ProgressState.
   */
  async update(progress: ScanProgress | ProgressState): Promise<void> {
    if (!this.spinner) {
      await this.start();
    }

    const state: ProgressState = {
      phase: progress.phase,
      module: progress.module,
      progressPercent: progress.progressPercent,
      message: progress.message,
      findingsCount: progress.findingsCount,
      endpointsTested: progress.endpointsTested,
      requestsSent: progress.requestsSent,
    };

    this.lastState = state;
    this.renderState(state);
  }

  /**
   * Renders the current state into the spinner text line.
   */
  private renderState(state: ProgressState): void {
    if (!this.spinner || !this.chalk) return;

    const elapsed = formatElapsed(Date.now() - this.startTime);
    const bar = renderProgressBar(state.progressPercent);
    const c = this.chalk;

    const line = [
      c.cyan.bold(`[${state.phase}]`),
      c.white(bar),
      c.gray("|"),
      c.yellow(`Module: ${state.module}`),
      c.gray("|"),
      c.green(`Findings: ${state.findingsCount}`),
      c.gray("|"),
      c.blue(`Reqs: ${state.requestsSent}`),
      c.gray("|"),
      c.magenta(`Endpoints: ${state.endpointsTested}`),
      c.gray("|"),
      c.gray(`Elapsed: ${elapsed}`),
    ].join(" ");

    this.spinner.text = line;
  }

  /**
   * Marks the scan as successfully completed. Stops the spinner with a success indicator.
   */
  async complete(summary?: string): Promise<void> {
    this.clearInterval();
    if (!this.spinner) return;

    const elapsed = formatElapsed(Date.now() - this.startTime);
    const c = this.chalk;
    const findings = this.lastState?.findingsCount ?? 0;
    const requests = this.lastState?.requestsSent ?? 0;

    const msg = summary
      ? summary
      : [
          c.green.bold("Scan completed"),
          c.gray("|"),
          c.green(`${findings} findings`),
          c.gray("|"),
          c.blue(`${requests} requests`),
          c.gray("|"),
          c.gray(`Duration: ${elapsed}`),
        ].join(" ");

    this.spinner.succeed(msg);
  }

  /**
   * Marks the scan as failed. Stops the spinner with an error indicator.
   */
  async error(msg: string): Promise<void> {
    this.clearInterval();
    if (!this.spinner) return;

    const c = this.chalk;
    this.spinner.fail(c.red.bold(`Scan failed: ${msg}`));
  }

  /**
   * Displays a warning without stopping the spinner.
   */
  async warn(msg: string): Promise<void> {
    if (!this.spinner) return;
    const c = this.chalk;
    this.spinner.warn(c.yellow(msg));
    // Re-start the spinner after warn (ora.warn stops it)
    this.spinner.start();
  }

  /**
   * Displays an informational message without stopping the spinner.
   */
  async info(msg: string): Promise<void> {
    if (!this.spinner) return;
    const c = this.chalk;
    this.spinner.info(c.cyan(msg));
    this.spinner.start();
  }

  /**
   * Returns the elapsed time in milliseconds since start().
   */
  getElapsedMs(): number {
    return Date.now() - this.startTime;
  }

  /**
   * Returns formatted elapsed time string.
   */
  getElapsedFormatted(): string {
    return formatElapsed(Date.now() - this.startTime);
  }

  private clearInterval(): void {
    if (this.intervalHandle) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
    }
  }
}

export { formatElapsed, renderProgressBar };
