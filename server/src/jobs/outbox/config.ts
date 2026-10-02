// =============================================================================
// Consumer of the apple-edge outbox: environment (OUTBOX_*, docs: file-durable
// annex A), parsed once and checked at start (config.ts startupConfigErrors).
// An invalid value is refused in every environment, development included.
// Self-contained (no import of the server's config, env or logger).
// =============================================================================

/** off (default): no consumer; on: consume, waiting for the table when it is
 *  missing; auto: consume when apple_edge.outbox exists at start. */
export type OutboxConsumerMode = 'off' | 'on' | 'auto';

export interface OutboxConfig {
  consumer: OutboxConsumerMode;
  /** Events per transaction (OUTBOX_BATCH_SIZE, 1 to 60, default 50): beyond
   *  64 savepoints that write, PostgreSQL overflows the subtransaction cache
   *  of the session (file-durable §7.1). */
  batchSize: number;
  /** Polling when no notification arrives (OUTBOX_POLL_MS, 500 to 10000,
   *  default 2000). */
  pollMs: number;
  /** Retention of the dead letters (OUTBOX_DEAD_LETTER_RETENTION_DAYS, 7 to
   *  180, default 30). */
  deadLetterRetentionDays: number;
  /** Age of an event not consumed (outside its attempts) that raises
   *  outbox:lag (OUTBOX_LAG_ALERT_SECONDS, 60 to 3600, default 300). */
  lagAlertSeconds: number;
}

export const OUTBOX_DEFAULTS: Readonly<OutboxConfig> = Object.freeze({
  consumer: 'off',
  batchSize: 50,
  pollMs: 2_000,
  deadLetterRetentionDays: 30,
  lagAlertSeconds: 300,
});

type Env = Record<string, string | undefined>;

function intIn(env: Env, name: string, min: number, max: number, fallback: number, errors: string[]): number {
  const raw = (env[name] ?? '').trim();
  if (raw === '') return fallback;
  if (!/^[0-9]+$/.test(raw) || Number(raw) < min || Number(raw) > max) {
    errors.push(`${name} must be an integer between ${min} and ${max} (${fallback} by default).`);
    return fallback;
  }
  return Number(raw);
}

/** The outbox settings of `env`, and why some are refused (empty: none). */
export function readOutboxConfig(env: Env = process.env): { config: OutboxConfig; errors: string[] } {
  const errors: string[] = [];
  const raw = (env.OUTBOX_CONSUMER ?? '').trim();
  let consumer: OutboxConsumerMode = OUTBOX_DEFAULTS.consumer;
  if (raw === 'off' || raw === 'on' || raw === 'auto') consumer = raw;
  else if (raw !== '') errors.push('OUTBOX_CONSUMER must be "off" (the default), "on" or "auto".');
  return {
    config: {
      consumer,
      batchSize: intIn(env, 'OUTBOX_BATCH_SIZE', 1, 60, OUTBOX_DEFAULTS.batchSize, errors),
      pollMs: intIn(env, 'OUTBOX_POLL_MS', 500, 10_000, OUTBOX_DEFAULTS.pollMs, errors),
      deadLetterRetentionDays: intIn(env, 'OUTBOX_DEAD_LETTER_RETENTION_DAYS', 7, 180, OUTBOX_DEFAULTS.deadLetterRetentionDays, errors),
      lagAlertSeconds: intIn(env, 'OUTBOX_LAG_ALERT_SECONDS', 60, 3_600, OUTBOX_DEFAULTS.lagAlertSeconds, errors),
    },
    errors,
  };
}
