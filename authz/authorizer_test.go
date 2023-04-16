package authz

import (
	"context"
	"github.com/shrinex/shield/authc"
	"github.com/stretchr/testify/assert"
	"testing"
)

type ud string

func (o ud) Principal() string {
	return string(o)
}

var mockUd = ud("mockUd")

type mockRealm struct {
}

func (r *mockRealm) LoadRoles(ctx context.Context, userDetails authc.UserDetails) ([]Role, error) {
	return []Role{role("a"), role("b"), role("c")}, nil
}

func (r *mockRealm) LoadAuthorities(ctx context.Context, userDetails authc.UserDetails) ([]Authority, error) {
	return []Authority{authority("create"), authority("read"), authority("write")}, nil
}

func TestHasRole(t *testing.T) {
	azer := NewAuthorizer(&mockRealm{})

	assert.True(t, azer.HasRole(context.Background(), mockUd, role("a")))
	assert.False(t, azer.HasRole(context.Background(), mockUd, role("d")))
}

func TestHasAnyRole(t *testing.T) {
	azer := NewAuthorizer(&mockRealm{})

	assert.True(t, azer.HasAnyRole(context.Background(), mockUd, role("a"), role("c")))
	assert.True(t, azer.HasAnyRole(context.Background(), mockUd, role("b"), role("d")))
	assert.False(t, azer.HasAnyRole(context.Background(), mockUd, role("e"), role("f")))
}

func TestHasAllRole(t *testing.T) {
	azer := NewAuthorizer(&mockRealm{})

	assert.True(t, azer.HasAllRole(context.Background(), mockUd, role("a"), role("c")))
	assert.False(t, azer.HasAllRole(context.Background(), mockUd, role("b"), role("d")))
	assert.False(t, azer.HasAllRole(context.Background(), mockUd, role("e"), role("f")))
}

func TestHasAuthority(t *testing.T) {
	azer := NewAuthorizer(&mockRealm{})

	assert.True(t, azer.HasAuthority(context.Background(), mockUd, authority("create")))
	assert.False(t, azer.HasAuthority(context.Background(), mockUd, authority("delete")))
}

func TestHasAnyAuthority(t *testing.T) {
	azer := NewAuthorizer(&mockRealm{})

	assert.True(t, azer.HasAnyAuthority(context.Background(), mockUd, authority("create"), authority("delete")))
	assert.True(t, azer.HasAnyAuthority(context.Background(), mockUd, authority("read"), authority("write")))
	assert.False(t, azer.HasAnyAuthority(context.Background(), mockUd, authority("delete"), authority("clear")))
}

func TestHasAllAuthority(t *testing.T) {
	azer := NewAuthorizer(&mockRealm{})

	assert.True(t, azer.HasAllAuthority(context.Background(), mockUd, authority("create"), authority("write")))
	assert.False(t, azer.HasAllAuthority(context.Background(), mockUd, authority("read"), authority("delete")))
	assert.False(t, azer.HasAllAuthority(context.Background(), mockUd, authority("delete"), authority("clear")))
}
