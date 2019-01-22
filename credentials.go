package socks5

import "context"

// CredentialStore is used to support user/pass authentication
type CredentialStore interface {
	Valid(ctx context.Context, user, password string) (context.Context, bool)
}

// StaticCredentials enables using a map directly as a credential store
type StaticCredentials map[string]string

func (s StaticCredentials) Valid(ctx context.Context, user, password string) (context.Context, bool) {
	pass, ok := s[user]
	if !ok {
		return ctx, false
	}
	return ctx, password == pass
}
