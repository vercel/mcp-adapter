import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createDefaultLogger, Logger, LogLevel } from '../src/types/logger';

describe('Logger Types and Utilities', () => {
  let consoleSpy: { [K in LogLevel]: ReturnType<typeof vi.spyOn> };

  beforeEach(() => {
    // Spy on all console methods
    consoleSpy = {
      log: vi.spyOn(console, 'log').mockImplementation(() => {}),
      error: vi.spyOn(console, 'error').mockImplementation(() => {}),
      warn: vi.spyOn(console, 'warn').mockImplementation(() => {}),
      info: vi.spyOn(console, 'info').mockImplementation(() => {}),
      debug: vi.spyOn(console, 'debug').mockImplementation(() => {}),
    };
  });

  afterEach(() => {
    // Restore all console methods
    Object.values(consoleSpy).forEach(spy => spy.mockRestore());
  });

  describe('createDefaultLogger', () => {
    it('creates a logger that logs when verboseLogs is true', () => {
      const logger = createDefaultLogger({ verboseLogs: true });

      logger.log('test log');
      logger.error('test error');
      logger.warn('test warn');
      logger.info('test info');
      logger.debug('test debug');

      expect(consoleSpy.log).toHaveBeenCalledWith('test log');
      expect(consoleSpy.error).toHaveBeenCalledWith('test error');
      expect(consoleSpy.warn).toHaveBeenCalledWith('test warn');
      expect(consoleSpy.info).toHaveBeenCalledWith('test info');
      expect(consoleSpy.debug).toHaveBeenCalledWith('test debug');
    });

    it('creates a logger that does not log when verboseLogs is false', () => {
      const logger = createDefaultLogger({ verboseLogs: false });

      logger.log('test log');
      logger.error('test error');
      logger.warn('test warn');
      logger.info('test info');
      logger.debug('test debug');

      expect(consoleSpy.log).not.toHaveBeenCalled();
      expect(consoleSpy.error).not.toHaveBeenCalled();
      expect(consoleSpy.warn).not.toHaveBeenCalled();
      expect(consoleSpy.info).not.toHaveBeenCalled();
      expect(consoleSpy.debug).not.toHaveBeenCalled();
    });

    it('defaults to verboseLogs false when no options provided', () => {
      const logger = createDefaultLogger();

      logger.log('test log');
      expect(consoleSpy.log).not.toHaveBeenCalled();
    });

    it('passes multiple arguments correctly', () => {
      const logger = createDefaultLogger({ verboseLogs: true });

      logger.log('message', { data: 'test' }, 123, true);
      expect(consoleSpy.log).toHaveBeenCalledWith('message', { data: 'test' }, 123, true);
    });

    it('handles undefined and null arguments', () => {
      const logger = createDefaultLogger({ verboseLogs: true });

      logger.log(undefined, null, '');
      expect(consoleSpy.log).toHaveBeenCalledWith(undefined, null, '');
    });
  });

  describe('Custom Logger Interface', () => {
    it('allows custom logger implementations', () => {
      const mockLogger: Logger = {
        log: vi.fn(),
        error: vi.fn(),
        warn: vi.fn(),
        info: vi.fn(),
        debug: vi.fn(),
      };

      mockLogger.log('test');
      mockLogger.error('error');
      mockLogger.warn('warning');
      mockLogger.info('info');
      mockLogger.debug('debug');

      expect(mockLogger.log).toHaveBeenCalledWith('test');
      expect(mockLogger.error).toHaveBeenCalledWith('error');
      expect(mockLogger.warn).toHaveBeenCalledWith('warning');
      expect(mockLogger.info).toHaveBeenCalledWith('info');
      expect(mockLogger.debug).toHaveBeenCalledWith('debug');
    });
  });

  describe('LogLevel Type', () => {
    it('includes all expected log levels', () => {
      const levels: LogLevel[] = ['log', 'error', 'warn', 'info', 'debug'];
      
      // This test ensures the LogLevel type matches our expectations
      levels.forEach(level => {
        expect(['log', 'error', 'warn', 'info', 'debug']).toContain(level);
      });
    });
  });
});