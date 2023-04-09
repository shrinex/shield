package semgr

import (
	"context"
	"sync"
	"time"
)

type (
	Repository interface {
		Save(context.Context, Session) error
		Remove(context.Context, string) error
		Read(context.Context, string) (Session, bool, error)
		Create(context.Context, string, time.Duration, time.Duration) (Session, error)
	}

	MapSessionRepository struct {
		mu        sync.RWMutex
		stopGuard sync.Once
		stopChan  chan struct{}
		lookup    map[string]*MapSession
	}
)

var _ Repository = (*MapSessionRepository)(nil)

func NewRepository() *MapSessionRepository {
	r := &MapSessionRepository{
		stopChan: make(chan struct{}),
		lookup:   make(map[string]*MapSession),
	}

	go r.startCleanup()

	return r
}

func (r *MapSessionRepository) Create(ctx context.Context, token string,
	timeout time.Duration, idleTimeout time.Duration) (Session, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	result := NewSession(token)
	_ = result.SetTimeout(ctx, timeout)
	_ = result.SetIdleTimeout(ctx, idleTimeout)
	r.lookup[token] = result

	return result, nil
}

func (r *MapSessionRepository) Read(ctx context.Context, key string) (Session, bool, error) {
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	default:
	}

	r.mu.RLock()
	src, ok := r.lookup[key]
	if !ok {
		r.mu.RUnlock()
		return nil, false, nil
	}

	expired, err := src.Expired(ctx)
	if err != nil {
		r.mu.RUnlock()
		return nil, false, err
	}

	if !expired {
		r.mu.RUnlock()
		return NewSessionCopy(src), true, nil
	}

	_ = src.Stop(ctx)
	_ = r.Remove(ctx, key)
	return nil, false, nil
}

func (r *MapSessionRepository) Save(ctx context.Context, session Session) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	src, ok := session.(*MapSession)
	if !ok {
		panic("only support *MapSession")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.lookup[src.Token()] = NewSessionCopy(src)

	return nil
}

func (r *MapSessionRepository) Remove(ctx context.Context, key string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.lookup[key]; ok {
		delete(r.lookup, key)
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
			_ = ss.Stop(ctx)
			delete(r.lookup, ss.Token())
		}
	}
}
