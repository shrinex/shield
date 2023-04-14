package authc

import (
	"context"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

type mockRealm struct {
	mock.Mock
}

func (r *mockRealm) Supports(token Token) bool {
	args := r.Called(token)
	return args.Bool(0)
}

func (r *mockRealm) LoadUserDetails(ctx context.Context, token Token) (UserDetails, error) {
	args := r.Called(ctx, token)

	err := args.Error(1)
	if err != nil {
		return nil, err
	}
	return args.Get(0).(UserDetails), nil
}

func TestAuthWhenInvalidTokenReturnsError(t *testing.T) {
	mr := &mockRealm{}
	ac := NewAuthenticator(mr)

	auth, err := ac.Authenticate(context.TODO(), NewBearerToken(""))
	assert.ErrorIs(t, err, ErrInvalidToken)
	assert.Nil(t, auth)
}

func TestAuthWithRealmNotSupport(t *testing.T) {
	mr := &mockRealm{}
	ac := NewAuthenticator(mr)
	tk := NewBearerToken("something")

	mr.On("Supports", mock.Anything).Return(false)

	auth, err := ac.Authenticate(context.TODO(), tk)
	assert.ErrorIs(t, err, ErrUnauthenticated)
	assert.Nil(t, auth)

	mr.AssertExpectations(t)
	mr.AssertNotCalled(t, "LoadUserDetails")
}

func TestAuthWithRealmReturnsError(t *testing.T) {
	mr := &mockRealm{}
	ac := NewAuthenticator(mr)
	tk := NewBearerToken("something")

	errFailed := errors.New("failed")
	mr.On("Supports", mock.Anything).
		Return(true).
		On("LoadUserDetails", context.TODO(), tk).
		Return(nil, errFailed)

	auth, err := ac.Authenticate(context.TODO(), tk)
	assert.ErrorIs(t, err, errFailed)
	assert.Nil(t, auth)

	mr.AssertExpectations(t)
}

func TestAuthWithRealmNoErr(t *testing.T) {
	mr := &mockRealm{}
	ac := NewAuthenticator(mr)
	tk := NewBearerToken("something")

	mr.On("Supports", mock.Anything).
		Return(true).
		On("LoadUserDetails", context.TODO(), tk).
		Return(tk, nil)

	auth, err := ac.Authenticate(context.TODO(), tk)
	assert.NoError(t, err)
	assert.NotNil(t, auth)

	mr.AssertExpectations(t)
}
