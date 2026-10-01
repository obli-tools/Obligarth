import pino from 'pino';
import { config } from '../config';
import { LOG_REDACT_CENSOR, LOG_REDACT_PATHS } from './logRedaction';

// Secrets and the rows copied by PostgreSQL into err.detail never reach a log
// line (coffre-secrets V18): utils/logRedaction.ts.
export const logger = pino({
  level: config.isDev ? 'debug' : 'info',
  redact: { paths: LOG_REDACT_PATHS, censor: LOG_REDACT_CENSOR },
  transport: config.isDev
    ? { target: 'pino-pretty', options: { colorize: true } }
    : undefined,
});
