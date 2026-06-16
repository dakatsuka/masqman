// Package auth defines browser authentication contracts and local credentials.
package auth

import (
	"context"
	"crypto/subtle"
	"errors"
)

// ErrInvalidCredentials reports an authentication failure without disclosing
// whether the username or password was wrong.
var ErrInvalidCredentials = errors.New("invalid credentials")

// User is the authenticated identity bound to issued MySQL one-time
// credentials and audit events.
type User struct {
	ID          string
	DisplayName string
}

// FlowProvider authenticates a browser login flow and returns the identity that
// downstream proxy sessions must audit.
type FlowProvider interface {
	Authenticate(ctx context.Context, username string, password string) (User, error)
}

// LocalUser is one username/password account loaded from development
// configuration.
type LocalUser struct {
	Username    string
	Password    string
	DisplayName string
}

// LocalProvider authenticates users against configured local credentials.
type LocalProvider struct {
	users map[string]LocalUser
}

// NewLocalProvider creates a local username/password authentication provider.
func NewLocalProvider(users []LocalUser) *LocalProvider {
	byName := make(map[string]LocalUser, len(users))
	for _, user := range users {
		byName[user.Username] = user
	}

	return &LocalProvider{users: byName}
}

// Authenticate verifies a configured local username/password pair.
func (p *LocalProvider) Authenticate(
	_ context.Context,
	username string,
	password string,
) (User, error) {
	user, ok := p.users[username]
	if !ok {
		return User{}, ErrInvalidCredentials
	}

	if subtle.ConstantTimeCompare([]byte(user.Password), []byte(password)) != 1 {
		return User{}, ErrInvalidCredentials
	}

	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.Username
	}

	return User{ID: user.Username, DisplayName: displayName}, nil
}
