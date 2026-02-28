package scanner

import (
	"net/http"
	"strings"
)

// AuthOptions holds optional authentication credentials injected into every
// HTTP request made by all scanner layers.
type AuthOptions struct {
	// Header is a raw "Name: Value" header string, e.g. "X-API-Key: mykey" or
	// "Authorization: Bearer tok". If both Header and Token are set, Header wins.
	Header string
	// Token is shorthand for "Authorization: Bearer <token>".
	Token string
	// Cookie is a raw Cookie header value, e.g. "session=abc; csrftoken=xyz".
	Cookie string
}

// IsEmpty returns true when no auth credentials are configured.
func (a AuthOptions) IsEmpty() bool {
	return a.Header == "" && a.Token == "" && a.Cookie == ""
}

// authTransport injects authentication headers into every outgoing HTTP request.
type authTransport struct {
	base http.RoundTripper
	opts AuthOptions
}

// NewAuthTransport wraps base with auth header injection.
// If opts is empty, base is returned unchanged (zero overhead when auth is not used).
func NewAuthTransport(base http.RoundTripper, opts AuthOptions) http.RoundTripper {
	if opts.IsEmpty() {
		return base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &authTransport{base: base, opts: opts}
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())

	if t.opts.Header != "" {
		parts := strings.SplitN(t.opts.Header, ":", 2)
		if len(parts) == 2 {
			r2.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	} else if t.opts.Token != "" {
		r2.Header.Set("Authorization", "Bearer "+t.opts.Token)
	}

	if t.opts.Cookie != "" {
		if existing := r2.Header.Get("Cookie"); existing != "" {
			r2.Header.Set("Cookie", existing+"; "+t.opts.Cookie)
		} else {
			r2.Header.Set("Cookie", t.opts.Cookie)
		}
	}

	return t.base.RoundTrip(r2)
}
