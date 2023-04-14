package semgt

import (
	"context"
	"github.com/google/uuid"
	"github.com/shrinex/shield/codec"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestSaveNoErr(t *testing.T) {
	repo := NewRepository(codec.NewCodec(), time.Duration(10), time.Duration(2))

	err := repo.Save(context.TODO(), NewSession(uuid.NewString(), repo.codec))
	assert.NoError(t, err)
}

func TestReadNil(t *testing.T) {
	repo := NewRepository(codec.NewCodec(), time.Duration(10), time.Duration(2))

	ss, err := repo.Read(context.TODO(), uuid.NewString())
	assert.NoError(t, err)
	assert.Nil(t, ss)
}

func TestReadLastSave(t *testing.T) {
	repo := NewRepository(codec.NewCodec(), time.Duration(10), time.Duration(2))

	key := uuid.NewString()
	lhs := NewSession(key, repo.codec)
	_ = repo.Save(context.TODO(), lhs)
	rhs, err := repo.Read(context.TODO(), key)
	assert.NoError(t, err)
	assert.NotNil(t, rhs)
	assert.Equal(t, lhs, rhs)
}

func TestRemoveWhenNotExists(t *testing.T) {
	repo := NewRepository(codec.NewCodec(), time.Duration(10), time.Duration(2))

	err := repo.Remove(context.TODO(), uuid.NewString())
	assert.NoError(t, err)
}

func TestRemoveLastSave(t *testing.T) {
	repo := NewRepository(codec.NewCodec(), time.Duration(10), time.Duration(2))

	key := uuid.NewString()
	lhs := NewSession(key, repo.codec)
	_ = repo.Save(context.TODO(), lhs)
	err := repo.Remove(context.TODO(), key)
	assert.NoError(t, err)
}
