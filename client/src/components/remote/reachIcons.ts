import { createLucideIcon } from 'lucide-react';

/**
 * Mouse pointer with a slash: the viewer's "view only" (the mouse and the
 * keyboard stay on this computer). lucide-react 0.344 has no
 * MousePointerBan; same drawing as the Oblireach Desktop viewer's button.
 */
export const MousePointerOff = createLucideIcon('MousePointerOff', [
  ['path', { d: 'M7 3v14l3.5-3.2 2.5 5.4 2-.9-2.5-5.3H18z', key: 'pointer' }],
  ['line', { x1: '3', y1: '3', x2: '21', y2: '21', key: 'slash' }],
]);
