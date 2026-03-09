package accessctl

import "context"

type ctxKey struct{}

// WithPolicy returns a new context carrying the given access policy.
func WithPolicy(ctx context.Context, p *Policy) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// PolicyFromContext retrieves the access policy from the context, or nil.
func PolicyFromContext(ctx context.Context) *Policy {
	p, _ := ctx.Value(ctxKey{}).(*Policy)
	return p
}
