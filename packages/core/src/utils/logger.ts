import pino from "pino";

const level = process.env.LOG_LEVEL || "info";

export const logger = pino({
  level,
  transport:
    process.env.NODE_ENV !== "production"
      ? { target: "pino-pretty", options: { colorize: true } }
      : undefined,
  formatters: {
    level: (label) => ({ level: label }),
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

export function createLogger(module: string) {
  return logger.child({ module });
}
