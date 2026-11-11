// ── Session reset ───────────────────────────────────────────────────────────
// The stores that hold data of the signed-in account (alerts, tenants, group
// tree, MCP notices…) register here how to return to their initial state.
// authStore runs them on logout and before a new sign-in, so that an account
// signing in in the same tab never sees what the previous one had loaded.
// This module imports nothing, so that any store can use it without a cycle.

type SessionResetListener = () => void;

const resetListeners = new Set<SessionResetListener>();

/** Registers a reset of the account's data; returns the unregister function. */
export function onSessionReset(listener: SessionResetListener): () => void {
  resetListeners.add(listener);
  return () => { resetListeners.delete(listener); };
}

/** Returns every registered store to its initial state (one failing does not stop the others). */
export function resetSession(): void {
  for (const listener of resetListeners) {
    try {
      listener();
    } catch {
      // a store failing to reset must not keep the others' data
    }
  }
}
