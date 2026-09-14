package dnsresolver

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Budget limits the total number of queries a scan may issue. Once the limit
// is reached every further lookup fails with KindBudget without touching the
// network.
type Budget struct {
	next  Resolver
	limit int64
	used  atomic.Int64
}

// WithBudget wraps r with a query budget of limit lookups.
func WithBudget(r Resolver, limit int) *Budget {
	return &Budget{next: r, limit: int64(limit)}
}

// Used returns the number of lookups attempted, including rejected ones.
func (b *Budget) Used() int { return int(b.used.Load()) }

// Sent returns the number of lookups passed on to the underlying resolver.
func (b *Budget) Sent() int { return int(min(b.used.Load(), b.limit)) }

// Exhausted reports whether any lookup was rejected by the budget.
func (b *Budget) Exhausted() bool { return b.used.Load() > b.limit }

func (b *Budget) take(name, typ string) error {
	if b.used.Add(1) > b.limit {
		return &Error{Kind: KindBudget, Name: Trim(name), Type: typ}
	}
	return nil
}

// LookupTXT implements Resolver.
func (b *Budget) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := b.take(name, "TXT"); err != nil {
		return nil, err
	}
	return b.next.LookupTXT(ctx, name)
}

// LookupMX implements Resolver.
func (b *Budget) LookupMX(ctx context.Context, name string) ([]MX, error) {
	if err := b.take(name, "MX"); err != nil {
		return nil, err
	}
	return b.next.LookupMX(ctx, name)
}

// LookupA implements Resolver.
func (b *Budget) LookupA(ctx context.Context, name string) ([]netip.Addr, error) {
	if err := b.take(name, "A"); err != nil {
		return nil, err
	}
	return b.next.LookupA(ctx, name)
}

// LookupAAAA implements Resolver.
func (b *Budget) LookupAAAA(ctx context.Context, name string) ([]netip.Addr, error) {
	if err := b.take(name, "AAAA"); err != nil {
		return nil, err
	}
	return b.next.LookupAAAA(ctx, name)
}

// LookupCNAME implements Resolver.
func (b *Budget) LookupCNAME(ctx context.Context, name string) (string, error) {
	if err := b.take(name, "CNAME"); err != nil {
		return "", err
	}
	return b.next.LookupCNAME(ctx, name)
}

// LookupPTR implements Resolver.
func (b *Budget) LookupPTR(ctx context.Context, addr netip.Addr) ([]string, error) {
	if err := b.take(ReverseName(addr), "PTR"); err != nil {
		return nil, err
	}
	return b.next.LookupPTR(ctx, addr)
}

// Cache memoises lookups for the lifetime of one scan, so that the same
// record consulted by several checks is fetched once and every check sees the
// same answer. Concurrent lookups of the same name share one query.
// Temporary failures other than budget rejections are not cached.
type Cache struct {
	next Resolver
	mu   sync.Mutex
	m    map[string]*cacheEntry
}

type cacheEntry struct {
	done chan struct{}
	val  any
	err  error
}

// NewCache wraps r with a per-scan cache.
func NewCache(r Resolver) *Cache {
	return &Cache{next: r, m: map[string]*cacheEntry{}}
}

func cached[T any](c *Cache, key string, fetch func() (T, error)) (T, error) {
	c.mu.Lock()
	if e, ok := c.m[key]; ok {
		c.mu.Unlock()
		<-e.done
		v, _ := e.val.(T)
		return v, e.err
	}
	e := &cacheEntry{done: make(chan struct{})}
	c.m[key] = e
	c.mu.Unlock()

	// Close the entry even if fetch panics, so that waiters never block.
	defer close(e.done)
	v, err := fetch()
	e.val, e.err = v, err
	if err != nil && IsTemporary(err) && KindOf(err) != KindBudget {
		// Waiters already blocked on this entry receive the failure; later
		// callers retry. Budget rejections are final for the scan and are
		// cached so that repeated lookups do not count again.
		c.mu.Lock()
		delete(c.m, key)
		c.mu.Unlock()
	}
	return v, err
}

// LookupTXT implements Resolver.
func (c *Cache) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return cached(c, "TXT "+Fqdn(name), func() ([]string, error) { return c.next.LookupTXT(ctx, name) })
}

// LookupMX implements Resolver.
func (c *Cache) LookupMX(ctx context.Context, name string) ([]MX, error) {
	return cached(c, "MX "+Fqdn(name), func() ([]MX, error) { return c.next.LookupMX(ctx, name) })
}

// LookupA implements Resolver.
func (c *Cache) LookupA(ctx context.Context, name string) ([]netip.Addr, error) {
	return cached(c, "A "+Fqdn(name), func() ([]netip.Addr, error) { return c.next.LookupA(ctx, name) })
}

// LookupAAAA implements Resolver.
func (c *Cache) LookupAAAA(ctx context.Context, name string) ([]netip.Addr, error) {
	return cached(c, "AAAA "+Fqdn(name), func() ([]netip.Addr, error) { return c.next.LookupAAAA(ctx, name) })
}

// LookupCNAME implements Resolver.
func (c *Cache) LookupCNAME(ctx context.Context, name string) (string, error) {
	return cached(c, "CNAME "+Fqdn(name), func() (string, error) { return c.next.LookupCNAME(ctx, name) })
}

// LookupPTR implements Resolver.
func (c *Cache) LookupPTR(ctx context.Context, addr netip.Addr) ([]string, error) {
	return cached(c, "PTR "+addr.String(), func() ([]string, error) { return c.next.LookupPTR(ctx, addr) })
}
