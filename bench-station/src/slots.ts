/**
 * Obligarth bench station — cards and their claims (lot BANC §5.4).
 *
 * One card per ADB SERIAL (`adb devices -l`), 16 at most. A serial belongs to one active card: a second claim is
 * `slot_held`; a 17th card is `too_many_cards`. Another serial on the same USB port is another card. A serial that
 * disappears keeps its card (the card holds: « appareil débranché ») until the same serial comes back or the
 * technician closes it.
 */
export const MAX_CARDS = 16;

export type ClaimRefusal = 'slot_held' | 'too_many_cards';

export class SlotBoard<T> {
  private readonly cards = new Map<string, T>();

  constructor(private readonly max = MAX_CARDS) {}

  get size(): number { return this.cards.size; }
  get(serial: string): T | undefined { return this.cards.get(serial); }
  values(): T[] { return [...this.cards.values()]; }
  has(serial: string): boolean { return this.cards.has(serial); }

  /** Claims a serial for a new card made by `make`; refuses a serial already held or a full board. */
  claim(serial: string, make: () => T): { ok: true; card: T } | { ok: false; code: ClaimRefusal } {
    if (this.cards.has(serial)) return { ok: false, code: 'slot_held' };
    if (this.cards.size >= this.max) return { ok: false, code: 'too_many_cards' };
    const card = make();
    this.cards.set(serial, card);
    return { ok: true, card };
  }

  release(serial: string): boolean { return this.cards.delete(serial); }
}
