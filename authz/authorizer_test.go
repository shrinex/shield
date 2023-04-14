package authz

import (
	"context"
	"github.com/stretchr/testify/assert"
	"testing"
)

var mockPrincipal = "mockPrincipal"

type mockRealm struct {
}

func (r *mockRealm) LoadRoles(ctx context.Context, principal string) ([]Role, error) {
	return []Role{role("a"), role("b"), role("c")}, nil
}

func (r *mockRealm) LoadAuthorities(ctx context.Context, principal string) ([]Authority, error) {
	return []Authority{authority("create"), authority("read"), authority("write")}, nil
}

func TestHasRole(t *testing.T) {
	azer := NewAuthorizer(&mockRealm{})

	assert.True(t, azer.HasRole(context.Background(), mockPrincipal, role("a")))
	assert.False(t, azer.HasRole(context.Background(), mockPrincipal, role("d")))
}

func TestHasAnyRole(t *testing.T) {
	azer := NewAuthorizer(&mockRealm{})

	assert.True(t, azer.HasAnyRole(context.Background(), mockPrincipal, role("a"), role("c")))
	assert.True(t, azer.HasAnyRole(context.Background(), mockPrincipal, role("b"), role("d")))
	assert.False(t, azer.HasAnyRole(context.Background(), mockPrincipal, role("e"), role("f")))
}

func TestHasAllRole(t *testing.T) {
	azer := NewAuthorizer(&mockRealm{})

	assert.True(t, azer.HasAllRole(context.Background(), mockPrincipal, role("a"), role("c")))
	assert.False(t, azer.HasAllRole(context.Background(), mockPrincipal, role("b"), role("d")))
	assert.False(t, azer.HasAllRole(context.Background(), mockPrincipal, role("e"), role("f")))
}

func TestHasAuthority(t *testing.T) {
	azer := NewAuthorizer(&mockRealm{})

	assert.True(t, azer.HasAuthority(context.Background(), mockPrincipal, authority("create")))
	assert.False(t, azer.HasAuthority(context.Background(), mockPrincipal, authority("delete")))
}

func TestHasAnyAuthority(t *testing.T) {
	azer := NewAuthorizer(&mockRealm{})

	assert.True(t, azer.HasAnyAuthority(context.Background(), mockPrincipal, authority("create"), authority("delete")))
	assert.True(t, azer.HasAnyAuthority(context.Background(), mockPrincipal, authority("read"), authority("write")))
	assert.False(t, azer.HasAnyAuthority(context.Background(), mockPrincipal, authority("delete"), authority("clear")))
}

func TestHasAllAuthority(t *testing.T) {
	azer := NewAuthorizer(&mockRealm{})

	assert.True(t, azer.HasAllAuthority(context.Background(), mockPrincipal, authority("create"), authority("write")))
	assert.False(t, azer.HasAllAuthority(context.Background(), mockPrincipal, authority("read"), authority("delete")))
	assert.False(t, azer.HasAllAuthority(context.Background(), mockPrincipal, authority("delete"), authority("clear")))
}
