// =============================================================================
// The position of a DeviceLocation answer (docs: integration-apple-edge §7.6,
// SEC-05), validated before it reaches lost_mode_locations: pure, no import (the
// local tests load it as is). Never a coordinate in the logs.
// =============================================================================

/** A device's clock this far ahead counts as the reception. */
const FUTURE_TOLERANCE_MS = 5 * 60_000;

/** A finite number (a plist real, or its text), or null. */
const numberOf = (v: unknown): number | null => {
  const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN;
  return Number.isFinite(n) ? n : null;
};
/** A measure the device reports as negative when it does not know it (accuracy, speed, course): null then. */
const measureOf = (v: unknown, max = 1e7): number | null => {
  const n = numberOf(v);
  return n === null || n < 0 || n > max ? null : n;
};
const timeOf = (v: unknown): Date | null => {
  const d = v instanceof Date ? v : typeof v === 'string' || typeof v === 'number' ? new Date(v) : null;
  return d && Number.isFinite(d.getTime()) ? d : null;
};

/** The position of a DeviceLocation answer, validated (pure): null when the coordinates are missing or out of bounds. */
export function locationOf(result: Record<string, unknown>, occurredAt: Date): {
  latitude: number; longitude: number; horizontalAccuracy: number | null; verticalAccuracy: number | null;
  altitude: number | null; speed: number | null; course: number | null; observedAt: Date;
} | null {
  const latitude = numberOf(result.Latitude);
  const longitude = numberOf(result.Longitude);
  if (latitude === null || longitude === null || latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) return null;
  const at = timeOf(result.Timestamp);
  const altitude = numberOf(result.Altitude);
  const course = measureOf(result.Course);
  return {
    latitude, longitude,
    horizontalAccuracy: measureOf(result.HorizontalAccuracy), verticalAccuracy: measureOf(result.VerticalAccuracy),
    altitude: altitude !== null && Math.abs(altitude) <= 1e6 ? altitude : null,
    speed: measureOf(result.Speed),
    course: course !== null && course <= 360 ? course : null,
    observedAt: at && at.getTime() <= occurredAt.getTime() + FUTURE_TOLERANCE_MS ? at : occurredAt,
  };
}
