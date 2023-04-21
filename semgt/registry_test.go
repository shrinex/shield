package semgt

import (
	"context"
	"github.com/shrinex/shield/codec"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestRegisterNoErr(t *testing.T) {
	ctx := context.Background()
	repository := NewRepository(codec.JSON, 10*time.Minute, time.Minute)
	session, _ := repository.Create(ctx, "abc")
	registry := NewRegistry(repository)

	err := registry.Register(ctx, "archer", session)
	assert.NoError(t, err)

	sign := signature{
		platform:  "universal",
		principal: "archer",
	}
	assert.Equal(t, 1, len(registry.lookup))
	assert.Equal(t, sign, registry.lookup["abc"])

	assert.Equal(t, 1, len(registry.signs))
	assert.Equal(t, 1, registry.signs[sign].Len())
	assert.Equal(t, "abc", registry.signs[sign].Back().Value)
}

func TestDeregister(t *testing.T) {
	ctx := context.Background()
	repository := NewRepository(codec.JSON, 10*time.Minute, time.Minute)
	session, _ := repository.Create(ctx, "abc")
	registry := NewRegistry(repository)

	_ = registry.Register(ctx, "archer", session)
	err := registry.Deregister(ctx, "archer", session)
	assert.NoError(t, err)

	assert.Empty(t, registry.lookup)
	assert.Empty(t, registry.signs)
}

func TestActiveSessions(t *testing.T) {
	ctx := context.Background()
	repository := NewRepository(codec.JSON, 10*time.Minute, time.Minute)
	session, _ := repository.Create(ctx, "abc")
	registry := NewRegistry(repository)

	_ = registry.Register(ctx, "archer", session)

	activeSessions, err := registry.ActiveSessions(ctx, "archer")
	assert.NoError(t, err)

	assert.Equal(t, 1, len(activeSessions))
	assert.Equal(t, session.token, activeSessions[0].token)
}

func TestActiveSessionsAfterExpire(t *testing.T) {
	defer func() { nowFunc = time.Now }()
	nowTime := time.Unix(0, 0)
	nowFunc = func() time.Time { return nowTime }

	ctx := context.Background()
	repository := NewRepository(codec.JSON, 10*time.Minute, time.Minute)
	session, _ := repository.Create(ctx, "abc")
	registry := NewRegistry(repository)

	_ = registry.Register(ctx, "archer", session)

	// all sessions are expired
	nowFunc = func() time.Time { return nowTime.Add(11 * time.Minute) }

	activeSessions, err := registry.ActiveSessions(ctx, "archer")
	assert.NoError(t, err)

	assert.Empty(t, activeSessions)
}

func TestAutoCleanUp(t *testing.T) {
	defer func() { nowFunc = time.Now }()
	nowTime := time.Unix(0, 0)
	nowFunc = func() time.Time { return nowTime }

	ctx := context.Background()
	repository := NewRepository(codec.JSON, 10*time.Minute, time.Minute)
	session, _ := repository.Create(ctx, "abc")
	registry := NewRegistry(repository)

	_ = registry.Register(ctx, "archer", session)

	// all sessions are expired
	nowFunc = func() time.Time { return nowTime.Add(11 * time.Minute) }
	// mock timer fires
	registry.deleteInactivated()

	assert.Empty(t, registry.lookup)
	assert.Empty(t, registry.signs)
}
