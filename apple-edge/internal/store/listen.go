package store

import (
	"context"
	"sync"
	"time"

	"github.com/lib/pq"
)

// Notification is a NOTIFY received on a channel. Reconnected is set (with
// no payload) after the listening connection was re-established:
// notifications may have been lost in between, subscribers reconcile.
type Notification struct {
	Payload     string
	Reconnected bool
}

// Hub shares one dedicated LISTEN connection (never pooled nor recycled)
// between the components of apple-edge.
type Hub struct {
	dsn  string
	logf func(msg string, err error)

	mu   sync.Mutex
	subs map[string][]chan Notification
}

// NewHub returns a hub; logf receives connection events (may be nil).
func NewHub(dsn string, logf func(msg string, err error)) *Hub {
	if logf == nil {
		logf = func(string, error) {}
	}
	return &Hub{dsn: dsn, logf: logf, subs: map[string][]chan Notification{}}
}

// Subscribe returns the notifications of channel. Call before Run.
func (h *Hub) Subscribe(channel string) <-chan Notification {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan Notification, 256)
	h.subs[channel] = append(h.subs[channel], ch)
	return ch
}

func (h *Hub) deliver(channel string, n Notification) {
	h.mu.Lock()
	subs := h.subs[channel]
	h.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- n:
		default: // a slow subscriber reconciles on its own timer
		}
	}
}

// Run listens until ctx ends.
func (h *Hub) Run(ctx context.Context) {
	l := pq.NewListener(h.dsn, time.Second, 30*time.Second, func(ev pq.ListenerEventType, err error) {
		switch ev {
		case pq.ListenerEventReconnected:
			h.logf("listener reconnected", nil)
		case pq.ListenerEventDisconnected, pq.ListenerEventConnectionAttemptFailed:
			h.logf("listener disconnected", err)
		}
	})
	defer l.Close()
	h.mu.Lock()
	channels := make([]string, 0, len(h.subs))
	for c := range h.subs {
		channels = append(channels, c)
	}
	h.mu.Unlock()
	for _, c := range channels {
		if err := l.Listen(c); err != nil {
			h.logf("listen "+c, err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case n := <-l.Notify:
			if n == nil { // connection re-established
				for _, c := range channels {
					h.deliver(c, Notification{Reconnected: true})
				}
				continue
			}
			h.deliver(n.Channel, Notification{Payload: n.Extra})
		}
	}
}
