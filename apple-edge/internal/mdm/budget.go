package mdm

import "sync"

// largeBudget bounds the memory taken by large bodies (decision AE-B0-R3,
// option A). A body above 1 MiB, or a property list above HeavyPlist
// nodes, reserves bytes before it is read or decoded: its announced length
// (or the route's limit when the length is unknown), at least 1 MiB. The
// reservations in flight are bounded overall (total), per tenant
// (perTenant) and in number (slots); and a device (its verified identity)
// holds at most one of them, so that one enrolled device can neither fill
// the process nor starve the other devices of its tenant. Decoding a
// command result costs about fourteen times its size (measured on lot C0:
// 228 MiB for a signed result of 16 MiB): total is sized from the memory
// limit of the process (GOMEMLIMIT), see config.DefaultLargeBodyBudget.
type largeBudget struct {
	mu        sync.Mutex
	total     int64
	perTenant int64
	slots     int
	used      int64
	n         int
	tenants   map[string]int64
	devices   map[string]struct{}
}

func newLargeBudget(total, perTenant int64, slots int) *largeBudget {
	return &largeBudget{total: total, perTenant: perTenant, slots: slots,
		tenants: make(map[string]int64), devices: make(map[string]struct{})}
}

// acquire reserves n bytes for tenant, without waiting.
func (b *largeBudget) acquire(tenant string, n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.n >= b.slots || b.used+n > b.total || b.tenants[tenant]+n > b.perTenant {
		return false
	}
	b.n++
	b.used += n
	b.tenants[tenant] += n
	return true
}

// release returns a reservation of acquire.
func (b *largeBudget) release(tenant string, n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.n--
	b.used -= n
	if b.tenants[tenant] -= n; b.tenants[tenant] <= 0 {
		delete(b.tenants, tenant)
	}
}

// holdDevice marks the device (the fingerprint of its verified identity)
// as holding a reservation; false if it already holds one.
func (b *largeBudget) holdDevice(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.devices[id]; ok {
		return false
	}
	b.devices[id] = struct{}{}
	return true
}

func (b *largeBudget) dropDevice(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.devices, id)
}

// inUse returns the bytes reserved and the number of reservations.
func (b *largeBudget) inUse() (int64, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used, b.n
}
