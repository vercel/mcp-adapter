import type { RedisClientType } from 'redis';

export interface SessionManager {
  sessionId: string;
  subscriptions: Set<string>;
  cleanup: () => Promise<void>;
  isActive: boolean;
  createdAt: number;
}

interface ConnectionMonitor {
  activeConnections: number;
  maxConnections: number;
  connectionHistory: Map<string, number>;
}

const activeSessions = new Map<string, SessionManager>();
const monitor: ConnectionMonitor = {
  activeConnections: 0,
  maxConnections: 100, // Default limit
  connectionHistory: new Map(),
};

export function createSessionManager(
  sessionId: string,
  redis: RedisClientType,
  logger?: { log: (...args: unknown[]) => void; error: (...args: unknown[]) => void }
): SessionManager {
  const subscriptions = new Set<string>();
  let isActive = true;
  const createdAt = Date.now();

  const cleanup = async (): Promise<void> => {
    if (!isActive) return;

    try {
      isActive = false;

      // Unsubscribe from all channels for this session
      const channelsToUnsubscribe = Array.from(subscriptions);
      if (channelsToUnsubscribe.length > 0) {
        for (const channel of channelsToUnsubscribe) {
          try {
            await redis.unsubscribe(channel);
          } catch (error) {
            logger?.error(`Failed to unsubscribe from ${channel}:`, error);
          }
        }
        logger?.log(`Cleaned up ${channelsToUnsubscribe.length} subscriptions for session ${sessionId}`);
      }

      subscriptions.clear();
      activeSessions.delete(sessionId);
      releaseConnection(sessionId);
    } catch (error) {
      logger?.error(`Failed to cleanup session ${sessionId}:`, error);
    }
  };

  const manager: SessionManager = {
    sessionId,
    subscriptions,
    cleanup,
    isActive,
    createdAt
  };

  activeSessions.set(sessionId, manager);
  trackConnection(sessionId);

  return manager;
}

// Enhanced subscription function with tracking
export async function subscribeWithTracking(
  redis: RedisClientType,
  sessionManager: SessionManager,
  channel: string,
  callback: (message: string) => void,
  logger?: { log: (...args: unknown[]) => void; error: (...args: unknown[]) => void }
): Promise<void> {
  if (!sessionManager.isActive) {
    throw new Error(`Cannot subscribe to ${channel}: session ${sessionManager.sessionId} is not active`);
  }

  await redis.subscribe(channel, callback);
  sessionManager.subscriptions.add(channel);

  logger?.log(`Subscribed to ${channel} for session ${sessionManager.sessionId}`);
}

// Enhanced unsubscription with tracking
export async function unsubscribeWithTracking(
  redis: RedisClientType,
  sessionManager: SessionManager,
  channel: string,
  logger?: { log: (...args: unknown[]) => void; error: (...args: unknown[]) => void }
): Promise<void> {
  try {
    await redis.unsubscribe(channel);
    sessionManager.subscriptions.delete(channel);

    logger?.log(`Unsubscribed from ${channel} for session ${sessionManager.sessionId}`);
  } catch (error) {
    logger?.error(`Failed to unsubscribe from ${channel}:`, error);
  }
}

// Connection monitoring functions
export function checkConnectionLimit(): boolean {
  return monitor.activeConnections < monitor.maxConnections;
}

export function trackConnection(sessionId: string): void {
  monitor.activeConnections++;
  monitor.connectionHistory.set(sessionId, Date.now());

  // Clean old connection history (older than 1 hour)
  const oneHourAgo = Date.now() - (60 * 60 * 1000);
  for (const [id, timestamp] of monitor.connectionHistory.entries()) {
    if (timestamp < oneHourAgo) {
      monitor.connectionHistory.delete(id);
    }
  }
}

export function releaseConnection(sessionId: string): void {
  monitor.activeConnections = Math.max(0, monitor.activeConnections - 1);
  monitor.connectionHistory.delete(sessionId);
}

export function getConnectionStats() {
  return {
    active: monitor.activeConnections,
    max: monitor.maxConnections,
    historySize: monitor.connectionHistory.size,
    sessions: Array.from(activeSessions.keys()),
    oldestSession: Math.min(...Array.from(activeSessions.values()).map(s => s.createdAt)),
  };
}

export function setMaxConnections(limit: number): void {
  monitor.maxConnections = limit;
}

// Cleanup stale sessions (sessions older than specified time)
export async function cleanupStaleSessions(maxAgeMs: number = 60 * 60 * 1000): Promise<number> {
  const now = Date.now();
  const staleSessions: SessionManager[] = [];

  for (const session of activeSessions.values()) {
    if (now - session.createdAt > maxAgeMs) {
      staleSessions.push(session);
    }
  }

  const cleanupPromises = staleSessions.map(session => session.cleanup());
  await Promise.all(cleanupPromises);

  return staleSessions.length;
}

// Cleanup all sessions (for graceful shutdown)
export async function cleanupAllSessions(): Promise<void> {
  const cleanupPromises = Array.from(activeSessions.values()).map(session => session.cleanup());
  await Promise.all(cleanupPromises);
  console.log('All sessions cleaned up');
}

// Get session by ID
export function getSession(sessionId: string): SessionManager | undefined {
  return activeSessions.get(sessionId);
}

// Get all active sessions
export function getAllSessions(): SessionManager[] {
  return Array.from(activeSessions.values());
}