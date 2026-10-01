package ade

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	depclient "github.com/micromdm/nanodep/client"
	"github.com/micromdm/nanodep/godep"
)

// protocolTransport sets X-Server-Protocol-Version on every request,
// /session included (NanoDEP's transport only defaults it to 7).
type protocolTransport struct {
	next    http.RoundTripper
	version string
}

func (t protocolTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Header.Set(depclient.ServerProtocolVersion, t.version)
	return t.next.RoundTrip(r2)
}

// NewHTTPClient returns the HTTP client of the ADE API.
func NewHTTPClient(protocolVersion int) *http.Client {
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 4,
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: protocolTransport{next: tr, version: strconv.Itoa(protocolVersion)}}
}

// tokenStore implements godep.ClientStorage: OAuth secrets are decrypted
// from apple_edge.ade_tokens when a session is opened; the base URL is the
// instance setting (EDGE_ADE_BASE_URL).
type tokenStore struct {
	s *Service
}

func (t tokenStore) RetrieveAuthTokens(ctx context.Context, name string) (*depclient.OAuth1Tokens, error) {
	return t.s.oauthTokens(ctx, name)
}

func (t tokenStore) RetrieveConfig(context.Context, string) (*depclient.Config, error) {
	return &depclient.Config{BaseURL: t.s.BaseURL}, nil
}

// staticStore serves tokens not stored yet (validation of a new token).
type staticStore struct {
	tokens *depclient.OAuth1Tokens
	base   string
}

func (s staticStore) RetrieveAuthTokens(context.Context, string) (*depclient.OAuth1Tokens, error) {
	return s.tokens, nil
}

func (s staticStore) RetrieveConfig(context.Context, string) (*depclient.Config, error) {
	return &depclient.Config{BaseURL: s.base}, nil
}

func (s *Service) newClient(st godep.ClientStorage) *godep.Client {
	return godep.NewClient(st, godep.WithClient(s.HTTP), godep.WithUserAgent(s.UserAgent))
}

// Kinds of ADE API failures.
type Kind int

const (
	KindTransient Kind = iota
	KindTerms
	KindAccessDenied
	KindUnauthorized
	KindRejected
)

// Error codes kept in last_error and events (never a response body).
const (
	CodeTermsNotSigned = "t_c_not_signed"
	CodeAccessDenied   = "access_denied"
	CodeUnauthorized   = "unauthorized"
	CodeServer         = "server_error"
	CodeTransport      = "transport"
)

// Classify maps an ADE API error to a kind and a code.
func Classify(err error) (Kind, string) {
	var he *godep.HTTPError
	var ae *depclient.AuthError
	var status int
	var body []byte
	switch {
	case errors.As(err, &he):
		status, body = he.StatusCode, he.Body
	case errors.As(err, &ae):
		status, body = ae.StatusCode, ae.Body
	case errors.Is(err, depclient.ErrEmptyAuthSessionToken):
		return KindUnauthorized, CodeUnauthorized
	default:
		return KindTransient, CodeTransport
	}
	switch {
	case bytes.Contains(body, []byte("T_C_NOT_SIGNED")):
		return KindTerms, CodeTermsNotSigned
	case status == http.StatusForbidden && bytes.Contains(body, []byte("ACCESS_DENIED")):
		return KindAccessDenied, CodeAccessDenied
	case status == http.StatusUnauthorized, status == http.StatusForbidden && ae != nil:
		return KindUnauthorized, CodeUnauthorized
	case status == http.StatusForbidden:
		return KindAccessDenied, CodeAccessDenied
	case status >= 500 || status == http.StatusTooManyRequests:
		return KindTransient, CodeServer
	}
	return KindRejected, "http_" + strconv.Itoa(status)
}

// oauthTokens decrypts the OAuth secrets of a live token.
func (s *Service) oauthTokens(ctx context.Context, id string) (*depclient.OAuth1Tokens, error) {
	var tenant string
	var enc *string
	err := s.DB.QueryRowContext(ctx, `SELECT tenant_key, oauth_enc FROM apple_edge.ade_tokens WHERE id = $1 AND state <> 'removed'`, id).Scan(&tenant, &enc)
	if err != nil {
		return nil, err
	}
	if enc == nil {
		return nil, errors.New("ade: token without OAuth secrets")
	}
	raw, err := s.Keys.Open(ctx, s.DB, tenant, tokensTable, "oauth_enc", id, *enc)
	if err != nil {
		return nil, err
	}
	var t depclient.OAuth1Tokens
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, err
	}
	return &t, nil
}
