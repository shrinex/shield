package semgt

import (
	"context"
	"github.com/google/uuid"
	"github.com/shrinex/shield/codec"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewSession(t *testing.T) {
	defer func() { nowFunc = time.Now }()
	nowTime := time.Unix(0, 0)
	nowFunc = func() time.Time { return nowTime }

	ctx := context.TODO()
	key := uuid.NewString()
	ss := NewSession(key, codec.NewCodec())

	assert.Equal(t, key, ss.Token())

	startTime, err := ss.StartTime(ctx)
	assert.NoError(t, err)
	assert.Equal(t, nowTime, startTime)

	lastAccessTime, err := ss.LastAccessTime(ctx)
	assert.NoError(t, err)
	assert.Equal(t, nowTime, lastAccessTime)

	keys, err := ss.AttributeKeys(ctx)
	assert.NoError(t, err)
	assert.Empty(t, keys)

	timeout, err := ss.Timeout(ctx)
	assert.NoError(t, err)
	assert.Equal(t, time.Duration(0), timeout)

	idleTimeout, err := ss.IdleTimeout(ctx)
	assert.NoError(t, err)
	assert.Equal(t, time.Duration(0), idleTimeout)
}

func TestSetAttrNoErr(t *testing.T) {
	ss := NewSession(uuid.NewString(), codec.NewCodec())

	err := ss.SetAttribute(context.TODO(), "key", "value")
	assert.NoError(t, err)
}

func TestGetAttrWhenNotExists(t *testing.T) {
	ss := NewSession(uuid.NewString(), codec.NewCodec())

	value, found, err := ss.AttributeAsString(context.TODO(), "key")
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Empty(t, value)
}

func TestGetAttrLastSet(t *testing.T) {
	ss := NewSession(uuid.NewString(), codec.NewCodec())

	_ = ss.SetAttribute(context.TODO(), "key", "value")
	value, found, err := ss.AttributeAsString(context.TODO(), "key")
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "value", value)
}
