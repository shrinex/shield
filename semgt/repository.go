package semgt

import (
	"context"
	"github.com/shrinex/shield/codec"
	"sync"
	"time"
)

type (
	Repository[S Session] interface {
		Save(context.Context, S) error
		Remove(context.Context, string) error
		Read(context.Context, string) (S, bool, error)
		Create(context.Context, string) (S, error)
	}

	MapSessionRepository struct {
		mu          sync.RWMutex
		stopGuard   sync.Once
		codec       codec.Codec
		stopChan    chan struct{}
		timeout     time.Duration
		idleTimeout time.Duration
		lookup      map[string]*MapSession
	}
)

var _ Repository[*MapSession] = (*MapSessionRepository)(nil)

func NewRepository(codec codec.Codec, timeout time.Duration,
	idleTimeout time.Duration) *MapSessionRepository {
	r := &MapSessionRepository{
		codec:       codec,
		timeout:     timeout,
		idleTimeout: idleTimeout,
		stopChan:    make(chan struct{}),
		lookup:      make(map[string]*MapSession),
	}

	go r.startCleanup()

	return r
}

func (r *MapSessionRepository) Create(ctx context.Context, token string) (*MapSession, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	result := NewSession(token, r.codec)
	_ = result.SetTimeout(ctx, r.timeout)
	_ = result.SetIdleTimeout(ctx, r.idleTimeout)
	r.lookup[token] = result

	return result, nil
}

func (r *MapSessionRepository) Read(ctx context.Context, token string) (*MapSession, bool, error) {
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	default:
	}

	r.mu.RLock()
	src, ok := r.lookup[token]
	r.mu.RUnlock()

	if !ok {
		return nil, false, nil
	}

	_, found, err := src.AttributeAsBool(ctx, AlreadyExpiredKey)
	if err != nil || found {
		return nil, false, err
	}

	expired, err := src.Expired(ctx)
	if err != nil {
		return nil, false, err
	}

	if expired {
		_ = src.SetAttribute(ctx, AlreadyExpiredKey, true)
		return nil, false, nil
	}

	return NewSessionCopy(src), true, nil
}

func (r *MapSessionRepository) Save(ctx context.Context, session *MapSession) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.lookup[session.Token()] = NewSessionCopy(session)

	return nil
}

func (r *MapSessionRepository) Remove(ctx context.Context, token string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.lookup[token]; ok {
		delete(r.lookup, token)
		return nil
	}

	return nil
}

func (r *MapSessionRepository) StopCleanup() error {
	r.stopGuard.Do(func() {
		close(r.stopChan)
	})

	return nil
}

func (r *MapSessionRepository) startCleanup() {
	ticker := time.NewTicker(5)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.deleteExpired()
		case <-r.stopChan:
			break
		}
	}
}

func (r *MapSessionRepository) deleteExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()

	ctx := context.TODO()
	for _, ss := range r.lookup {
		if expired, _ := ss.Expired(ctx); expired {
			_ = ss.SetAttribute(ctx, AlreadyExpiredKey, true)
			delete(r.lookup, ss.Token())
		}
	}
}
