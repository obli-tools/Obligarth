/**
 * The text of a CSV cell, neutralized when a spreadsheet would evaluate it: a
 * text value (not a number, a boolean or a date) whose text starts with = + -
 * @, a tab or a carriage return gets a leading apostrophe (OWASP, CSV
 * injection). The names of devices, end users and apps come from the devices:
 * a name such as `=HYPERLINK(…)` must never run when the file is opened.
 */
export function csvSafeText(value: unknown, text: string): string {
  if (typeof value === 'number' || typeof value === 'boolean' || value instanceof Date) return text;
  return /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
}
