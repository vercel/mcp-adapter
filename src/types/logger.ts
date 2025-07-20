/**
 * Log levels supported by the MCP handler
 */
export type LogLevel = "log" | "error" | "warn" | "info" | "debug";

/**
 * Logger interface for custom logging implementations
 */
export interface Logger {
  /**
   * Log general information messages
   */
  log: (...args: unknown[]) => void;
  
  /**
   * Log error messages
   */
  error: (...args: unknown[]) => void;
  
  /**
   * Log warning messages
   */
  warn: (...args: unknown[]) => void;
  
  /**
   * Log informational messages
   */
  info: (...args: unknown[]) => void;
  
  /**
   * Log debug messages
   */
  debug: (...args: unknown[]) => void;
}

/**
 * Options for creating a default console logger
 */
export interface DefaultLoggerOptions {
  /**
   * Whether to enable verbose logging to console
   * @default false
   */
  verboseLogs?: boolean;
}

/**
 * Creates a default console-based logger implementation
 * 
 * @param options - Configuration options for the default logger
 * @returns A Logger instance that logs to the console
 */
export function createDefaultLogger(options: DefaultLoggerOptions = {}): Logger {
  const { verboseLogs = false } = options;
  
  return {
    log: (...args: unknown[]) => {
      if (verboseLogs) console.log(...args);
    },
    error: (...args: unknown[]) => {
      if (verboseLogs) console.error(...args);
    },
    warn: (...args: unknown[]) => {
      if (verboseLogs) console.warn(...args);
    },
    info: (...args: unknown[]) => {
      if (verboseLogs) console.info(...args);
    },
    debug: (...args: unknown[]) => {
      if (verboseLogs) console.debug(...args);
    },
  };
}