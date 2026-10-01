// Package reqctx carries per-request values shared by several layers.
package reqctx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
)

type ctxKeyRequestID struct{}

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

// NewRequestID returns a random request id (32 hex characters).
func NewRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// RequestIDFromHeader keeps a well-formed incoming X-Request-ID, or makes one.
func RequestIDFromHeader(h string) string {
	if requestIDRe.MatchString(h) {
		return h
	}
	return NewRequestID()
}

// WithRequestID returns ctx carrying id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID{}, id)
}

// RequestID returns the request id of ctx ("" if none).
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyRequestID{}).(string)
	return id
}
