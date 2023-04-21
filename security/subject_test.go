package security

import (
	"context"
	"github.com/shrinex/shield/authc"
	"github.com/shrinex/shield/codec"
	"github.com/shrinex/shield/semgt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type mockRealm struct {
}

func (r *mockRealm) Supports(token authc.Token) bool {
	return true
}

func (r *mockRealm) LoadUserDetails(ctx context.Context, token authc.Token) (authc.UserDetails, error) {
	return token, nil
}

func TestLogin(t *testing.T) {
	token := authc.NewUsernamePasswordToken("archer", "123")
	repository := semgt.NewRepository(codec.JSON, 10*time.Minute, time.Minute)
	authenticator := authc.NewAuthenticator(&mockRealm{})
	registry := semgt.NewRegistry(repository)
	ctx := context.Background()

	sb := &subject[*semgt.MapSession]{
		authenticator: authenticator,
		repository:    repository,
		registry:      registry,
	}

	ctx, err := sb.Login(ctx, token, WithPlatform("mobile"), WithRenewToken())
	assert.NoError(t, err)
	assert.True(t, sb.Authenticated(ctx))

	userDetails, err := sb.UserDetails(ctx)
	assert.NoError(t, err)
	assert.Equal(t, token, userDetails)
}

func TestExclusive(t *testing.T) {
	GetGlobalOptions().Concurrency = 2

	token := authc.NewUsernamePasswordToken("archer", "123")
	repository := semgt.NewRepository(codec.JSON, 10*time.Minute, time.Minute)
	authenticator := authc.NewAuthenticator(&mockRealm{})
	registry := semgt.NewRegistry(repository)
	ctx := context.Background()

	sb := &subject[*semgt.MapSession]{
		authenticator: authenticator,
		repository:    repository,
		registry:      registry,
	}

	ctx, err := sb.Login(ctx, token, WithPlatform("mobile"), WithRenewToken())
	assert.NoError(t, err)
	prevSession, err := sb.Session(ctx)
	assert.NoError(t, err)

	ctx, err = sb.Login(ctx, token, WithPlatform("mobile"), WithRenewToken())
	assert.NoError(t, err)
	assert.True(t, sb.Authenticated(ctx))

	ss, err := repository.Read(ctx, prevSession.Token())
	assert.NoError(t, err)
	assert.Nil(t, ss)

	replaced, ok, err := prevSession.AttributeAsBool(ctx, semgt.AlreadyReplacedKey)
	assert.ErrorIs(t, err, semgt.ErrReplaced)
	assert.False(t, ok)
	assert.False(t, replaced)

	curSession, err := sb.Session(ctx)
	assert.NoError(t, err)

	sessions, err := registry.ActiveSessions(ctx, "archer")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(sessions))
	assert.Equal(t, curSession, sessions[0])

	ctx, err = sb.Login(ctx, token, WithPlatform("mobile"), WithRenewToken())
	assert.NoError(t, err)
	assert.True(t, sb.Authenticated(ctx))

	replaced, ok, err = curSession.AttributeAsBool(ctx, semgt.AlreadyReplacedKey)
	assert.ErrorIs(t, err, semgt.ErrReplaced)
	assert.False(t, ok)
	assert.False(t, replaced)
}

func TestExclusiveWithMultiPlatform(t *testing.T) {
	GetGlobalOptions().Concurrency = 2

	token := authc.NewUsernamePasswordToken("archer", "123")
	repository := semgt.NewRepository(codec.JSON, 10*time.Minute, time.Minute)
	authenticator := authc.NewAuthenticator(&mockRealm{})
	registry := semgt.NewRegistry(repository)
	ctx := context.Background()

	sb := &subject[*semgt.MapSession]{
		authenticator: authenticator,
		repository:    repository,
		registry:      registry,
	}

	ctx, err := sb.Login(ctx, token, WithPlatform("mobile"), WithRenewToken())
	assert.NoError(t, err)
	firstSession, err := sb.Session(ctx)
	assert.NoError(t, err)

	ctx, err = sb.Login(ctx, token, WithPlatform("web"), WithRenewToken())
	assert.NoError(t, err)
	secondSession, err := sb.Session(ctx)
	assert.NoError(t, err)

	ctx, err = sb.Login(ctx, token, WithPlatform("mobile"), WithRenewToken())
	assert.NoError(t, err)
	assert.True(t, sb.Authenticated(ctx))

	ss, err := repository.Read(ctx, firstSession.Token())
	assert.NoError(t, err)
	assert.Nil(t, ss)

	replaced, ok, err := firstSession.AttributeAsBool(ctx, semgt.AlreadyReplacedKey)
	assert.ErrorIs(t, err, semgt.ErrReplaced)
	assert.False(t, ok)
	assert.False(t, replaced)

	replaced, ok, err = secondSession.AttributeAsBool(ctx, semgt.AlreadyReplacedKey)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.False(t, replaced)

	curSession, err := sb.Session(ctx)
	assert.NoError(t, err)

	sessions, err := registry.ActiveSessions(ctx, "archer")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(sessions))
	assert.Equal(t, curSession, sessions[0])
}

func TestOverflow(t *testing.T) {
	GetGlobalOptions().Exclusive = false

	GetGlobalOptions().Concurrency = 1

	token := authc.NewUsernamePasswordToken("archer", "123")
	repository := semgt.NewRepository(codec.JSON, 10*time.Minute, time.Minute)
	authenticator := authc.NewAuthenticator(&mockRealm{})
	registry := semgt.NewRegistry(repository)
	ctx := context.Background()

	sb := &subject[*semgt.MapSession]{
		authenticator: authenticator,
		repository:    repository,
		registry:      registry,
	}

	ctx, err := sb.Login(ctx, token, WithPlatform("mobile"), WithRenewToken())
	assert.NoError(t, err)
	prevSession, err := sb.Session(ctx)
	assert.NoError(t, err)

	ctx, err = sb.Login(ctx, token, WithPlatform("mobile"), WithRenewToken())
	assert.NoError(t, err)
	assert.True(t, sb.Authenticated(ctx))

	ss, err := repository.Read(ctx, prevSession.Token())
	assert.NoError(t, err)
	assert.Nil(t, ss)

	overflow, ok, err := prevSession.AttributeAsBool(ctx, semgt.AlreadyOverflowKey)
	assert.ErrorIs(t, err, semgt.ErrOverflow)
	assert.False(t, ok)
	assert.False(t, overflow)

	curSession, err := sb.Session(ctx)
	assert.NoError(t, err)

	sessions, err := registry.ActiveSessions(ctx, "archer")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(sessions))
	assert.Equal(t, curSession, sessions[0])

	ctx, err = sb.Login(ctx, token, WithPlatform("mobile"), WithRenewToken())
	assert.NoError(t, err)
	assert.True(t, sb.Authenticated(ctx))

	overflow, ok, err = prevSession.AttributeAsBool(ctx, semgt.AlreadyOverflowKey)
	assert.ErrorIs(t, err, semgt.ErrOverflow)
	assert.False(t, ok)
	assert.False(t, overflow)
}
