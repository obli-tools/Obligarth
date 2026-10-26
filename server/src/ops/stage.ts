import { OBLIGARTH_STAGES, type ObligarthStage } from '@obligarth/shared';

// =============================================================================
// Stage of the instance (P0-13 D8: OBLIGARTH_STAGE = lab | pilot | production, lab by default). Read here, from the
// environment, by what already depends on it: the refusal of an enrollment while the notice of the tenant is not
// complete (D7, privacy/notice/provider.ts: a warning in lab, a refusal in pilot and production). P0-13 T11 moves the
// variable into config.ts, refuses an invalid value at start (startupConfigErrors) and adds the start-up checks of the
// stage; until then a value that is not one of the three is read as the strictest stage (production): a guard that
// fails closed, never open.
// No import of the configuration nor of the database: the unit tests load this file.
// =============================================================================

let override: ObligarthStage | null = null;

/** The stage of an environment: lab when OBLIGARTH_STAGE is absent or empty, production when it is not a stage. */
export function readInstanceStage(env: NodeJS.ProcessEnv): ObligarthStage {
  const raw = (env.OBLIGARTH_STAGE ?? '').trim().toLowerCase();
  if (raw === '') return 'lab';
  return (OBLIGARTH_STAGES as readonly string[]).includes(raw) ? raw as ObligarthStage : 'production';
}

/** The stage of this instance. */
export function instanceStage(): ObligarthStage {
  return override ?? readInstanceStage(process.env);
}

/** Is this instance past the laboratory (pilot or production)? */
export const beyondLab = (): boolean => instanceStage() !== 'lab';

/** Test hook: a fixed stage (null: the environment again). */
export function setInstanceStageForTests(stage: ObligarthStage | null): void {
  override = stage;
}
