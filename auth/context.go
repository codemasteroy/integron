package auth

import "context"

type claimsSinkKey struct{}

// ClaimsSink is a per-request holder that lets a Verifier (invoked deep inside
// openapi3filter request validation) hand the claims it established back to the
// HTTP handler without mutating the request.
type ClaimsSink struct {
	claims Claims
}

func (s *ClaimsSink) set(claims Claims) {
	if s != nil {
		s.claims = claims
	}
}

// Claims returns the claims recorded during authentication, or nil if none.
func (s *ClaimsSink) Claims() Claims {
	if s == nil {
		return nil
	}
	return s.claims
}

// WithClaimsSink returns a context carrying a fresh ClaimsSink and the sink
// itself. Pass the returned context to openapi3filter.ValidateRequest so that
// Authenticate can record claims into the sink.
func WithClaimsSink(ctx context.Context) (context.Context, *ClaimsSink) {
	sink := &ClaimsSink{}
	return context.WithValue(ctx, claimsSinkKey{}, sink), sink
}

func claimsSinkFrom(ctx context.Context) *ClaimsSink {
	sink, _ := ctx.Value(claimsSinkKey{}).(*ClaimsSink)
	return sink
}
