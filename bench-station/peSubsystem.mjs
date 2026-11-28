/**
 * Obligarth bench station — read and set the Windows subsystem of a PE executable (ported from the bench of Obliwan).
 *
 * `node.exe`, and therefore a Node SEA built from it, is a CONSOLE program (IMAGE_SUBSYSTEM_WINDOWS_CUI = 3): Windows
 * gives it a console window when it starts from Explorer. The station is a window application, so build.mjs rewrites
 * one 16-bit field of the optional header to IMAGE_SUBSYSTEM_WINDOWS_GUI = 2 and nothing else. The field sits at
 * offset 68 of the optional header in both PE32 and PE32+, which starts 24 bytes after the "PE\0\0" signature that
 * `e_lfanew` (offset 0x3C) points at. The header checksum is left as it is (checked only for drivers); the
 * Authenticode signature applied after this patch covers the patched bytes.
 */

export const SUBSYSTEM_GUI = 2;
export const SUBSYSTEM_CUI = 3;

function subsystemOffset(buf) {
  if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) throw new Error('not a PE file: no "MZ" header');
  const pe = buf.readUInt32LE(0x3c);
  if (pe + 24 + 70 > buf.length || buf.readUInt32LE(pe) !== 0x00004550) {
    throw new Error('not a PE file: no "PE\\0\\0" signature where e_lfanew points');
  }
  const optional = pe + 24;
  const magic = buf.readUInt16LE(optional);
  if (magic !== 0x10b && magic !== 0x20b) throw new Error(`unknown optional-header magic 0x${magic.toString(16)}`);
  return optional + 68;
}

export function readSubsystem(buf) {
  return buf.readUInt16LE(subsystemOffset(buf));
}

/** Set the subsystem in place; returns the previous value. */
export function setSubsystem(buf, value) {
  const at = subsystemOffset(buf);
  const previous = buf.readUInt16LE(at);
  buf.writeUInt16LE(value, at);
  return previous;
}
