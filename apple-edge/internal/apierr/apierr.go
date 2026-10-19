// Package apierr defines the errors the internal API turns into
// {"error": {"code": ..., "message": ...}} responses.
package apierr

import (
	"errors"
	"net/http"
)

// Error is an error with an HTTP status and a stable code.
type Error struct {
	Status  int
	Code    string
	Message string
	// Targets names the enrollments an error is about (422 target_outside_tenant
	// of the enqueue: README §10, point 19), at most MaxErrorTargets; nil for
	// the other errors.
	Targets []string
	// TargetsTruncated reports that more targets were refused than Targets lists.
	TargetsTruncated bool
}

// MaxErrorTargets bounds the targets an error names (the body stays small).
const MaxErrorTargets = 1000

// WithTargets returns a copy of e naming the refused targets (at most
// MaxErrorTargets of them).
func (e *Error) WithTargets(targets []string) *Error {
	c := *e
	if len(targets) > MaxErrorTargets {
		c.Targets = append([]string(nil), targets[:MaxErrorTargets]...)
		c.TargetsTruncated = true
	} else {
		c.Targets = append([]string(nil), targets...)
	}
	return &c
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// New returns an API error.
func New(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

// Common errors.
func BadRequest(msg string) *Error { return New(http.StatusBadRequest, "invalid_request", msg) }
func NotFound(code, msg string) *Error {
	return New(http.StatusNotFound, code, msg)
}
func Conflict(code, msg string) *Error { return New(http.StatusConflict, code, msg) }
func Unprocessable(code, msg string) *Error {
	return New(http.StatusUnprocessableEntity, code, msg)
}

// TenantNotFound is returned for an unknown or retired tenant.
var TenantNotFound = NotFound("tenant_not_found", "tenant not found")

// As returns the API error wrapped in err, if any.
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
