export type TaintState = 'CLEAN' | 'TAINTED';

interface SessionState {
  taint: TaintState;
  callCount: number;
  maxCalls: number;
  taintedAt?: string;
  taintReason?: string;
}

const sessions = new Map<string, SessionState>();

export function getOrCreateSession(sessionId: string, maxCalls: number): SessionState {
  let state = sessions.get(sessionId);
  if (!state) {
    state = { taint: 'CLEAN', callCount: 0, maxCalls };
    sessions.set(sessionId, state);
  }
  return state;
}

export function getTaint(sessionId: string): TaintState {
  return sessions.get(sessionId)?.taint ?? 'CLEAN';
}

export function markTainted(sessionId: string, reason: string): void {
  const state = sessions.get(sessionId);
  if (state && state.taint === 'CLEAN') {
    state.taint = 'TAINTED';
    state.taintedAt = new Date().toISOString();
    state.taintReason = reason;
  }
}

export function incrementCallCount(sessionId: string): { current: number; max: number; exceeded: boolean } {
  const state = sessions.get(sessionId);
  if (!state) return { current: 0, max: 0, exceeded: true };
  state.callCount++;
  return { current: state.callCount, max: state.maxCalls, exceeded: state.callCount > state.maxCalls };
}

export function getSessionState(sessionId: string): SessionState | undefined {
  return sessions.get(sessionId);
}

export function resetSession(sessionId: string): void {
  sessions.delete(sessionId);
}

export function allSessions(): Map<string, SessionState> {
  return sessions;
}
