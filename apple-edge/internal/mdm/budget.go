package mdm

import "sync"

// largeBudget bounds the memory taken by large bodies (decision AE-B0-R3,
// option A). A body above 1 MiB, or a property list above HeavyPlist
// nodes, reserves bytes before it is read or decoded: its announced length
// (or the route's limit when the length is unknown), at least 1 MiB. The
// reservations in flight are bounded overall (total), per tenant
// (perTenant) and in number (slots). Each is held on behalf of a holder
// that holds at most one: on the device routes, the identity of an
// enrolled device of the tenant (presumed from the Mdm-Signature header
// before the body is read, verified afterwards), so that one device can
// neither fill the process nor starve the other devices of its tenant, and
// an anonymous request gets no reservation at all (review of lot C0,
// AE-C0-R3); on the SCEP route, which is anonymous by nature, the source
// address, within an anonymous share of the total. Decoding a command
// result costs about fourteen times its size (measured on lot C0: 228 MiB
// for a signed result of 16 MiB): total is sized from the memory limit of
// the process (GOMEMLIMIT), see config.DefaultLargeBodyBudget.
type largeBudget struct {
	mu        sync.Mutex
	total     int64
	perTenant int64
	anonymous int64
	slots     int
	used      int64
	anonUsed  int64
	n         int
	tenants   map[string]int64
	holders   map[string]reservation
}

type reservation struct {
	tenant string
	n      int64
	anon   bool
}

// Outcomes of acquire.
const (
	largeOK = iota
	largeHeld
	largeFull
)

func newLargeBudget(total, perTenant int64, slots int) *largeBudget {
	return &largeBudget{total: total, perTenant: perTenant, anonymous: total / 4, slots: slots,
		tenants: make(map[string]int64), holders: make(map[string]reservation)}
}

// acquire reserves n bytes for tenant on behalf of holder, without
// waiting: largeHeld when the holder already holds a reservation,
// largeFull when there is no room (anon: within the anonymous share too).
func (b *largeBudget) acquire(tenant, holder string, n int64, anon bool) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.holders[holder]; ok {
		return largeHeld
	}
	if b.n >= b.slots || b.used+n > b.total || b.tenants[tenant]+n > b.perTenant || (anon && b.anonUsed+n > b.anonymous) {
		return largeFull
	}
	b.n++
	b.used += n
	b.tenants[tenant] += n
	if anon {
		b.anonUsed += n
	}
	b.holders[holder] = reservation{tenant: tenant, n: n, anon: anon}
	return largeOK
}

// release returns the reservation of holder, if any.
func (b *largeBudget) release(holder string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.holders[holder]
	if !ok {
		return
	}
	delete(b.holders, holder)
	b.n--
	b.used -= r.n
	if r.anon {
		b.anonUsed -= r.n
	}
	if b.tenants[r.tenant] -= r.n; b.tenants[r.tenant] <= 0 {
		delete(b.tenants, r.tenant)
	}
}

// inUse returns the bytes reserved and the number of reservations.
func (b *largeBudget) inUse() (int64, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used, b.n
}
