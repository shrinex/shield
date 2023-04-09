package semgr

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type (
	Session interface {
		Token() string
		StartTime(context.Context) (time.Time, error)
		Timeout(context.Context) (time.Duration, error)
		IdleTimeout(context.Context) (time.Duration, error)
		LastAccessTime(context.Context) (time.Time, error)
		Attribute(context.Context, string) (string, bool, error)
		SetAttribute(context.Context, string, string) error
		AttributeKeys(context.Context) ([]string, error)
		RemoveAttribute(context.Context, string) error
		Expired(context.Context) (bool, error)
		Touch(context.Context) error
		Stop(context.Context) error
	}

	MapSession struct {
		token          string
		mu             sync.RWMutex
		stopped        atomic.Int32
		startTime      time.Time
		lastAccessTime time.Time
		timeout        time.Duration
		idleTimeout    time.Duration
		attrs          map[string]string
	}
)

var _ Session = (*MapSession)(nil)

func NewSession(token string) *MapSession {
	nowTime := nowFunc()
	return &MapSession{
		token:          token,
		startTime:      nowTime,
		lastAccessTime: nowTime,
		attrs:          make(map[string]string),
	}
}

func NewSessionCopy(src *MapSession) *MapSession {
	s := &MapSession{
		token:          src.token,
		startTime:      src.startTime,
		lastAccessTime: src.lastAccessTime,
		timeout:        src.timeout,
		idleTimeout:    src.idleTimeout,
		attrs:          make(map[string]string),
	}

	for key, value := range src.attrs {
		s.attrs[key] = value
	}

	return s
}

func (s *MapSession) Token() string {
	return s.token
}

func (s *MapSession) StartTime(ctx context.Context) (time.Time, error) {
	if err := s.checkState(ctx); err != nil {
		return time.Time{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.startTime, nil
}

func (s *MapSession) Timeout(ctx context.Context) (time.Duration, error) {
	if err := s.checkState(ctx); err != nil {
		return time.Duration(0), err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.timeout, nil
}

func (s *MapSession) IdleTimeout(ctx context.Context) (time.Duration, error) {
	if err := s.checkState(ctx); err != nil {
		return time.Duration(0), err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.idleTimeout, nil
}

func (s *MapSession) LastAccessTime(ctx context.Context) (time.Time, error) {
	if err := s.checkState(ctx); err != nil {
		return time.Time{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.lastAccessTime, nil
}

func (s *MapSession) Expired(ctx context.Context) (bool, error) {
	if err := s.checkState(ctx); err != nil {
		return false, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	nowTime := nowFunc()
	timedOut := s.startTime.Add(s.timeout).Before(nowTime)
	inactive := s.lastAccessTime.Add(s.idleTimeout).Before(nowTime)

	return timedOut || inactive, nil
}

func (s *MapSession) Attribute(ctx context.Context, key string) (string, bool, error) {
	if err := s.checkState(ctx); err != nil {
		return "", false, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if value, ok := s.attrs[key]; ok {
		return value, true, nil
	}

	return "", false, nil
}

func (s *MapSession) AttributeKeys(ctx context.Context) ([]string, error) {
	if err := s.checkState(ctx); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0)
	for key := range s.attrs {
		keys = append(keys, key)
	}

	return keys, nil
}

func (s *MapSession) SetAttribute(ctx context.Context, key string, value string) error {
	if err := s.checkState(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(value) == 0 {
		delete(s.attrs, key)
	} else {
		s.attrs[key] = value
	}

	return nil
}

func (s *MapSession) RemoveAttribute(ctx context.Context, key string) error {
	if err := s.checkState(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.attrs, key)

	return nil
}

func (s *MapSession) Touch(ctx context.Context) error {
	return s.SetLastAccessTime(ctx, nowFunc())
}

func (s *MapSession) Stop(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.stopped.Store(1)

	return nil
}

//=====================================
//		      Setters
//=====================================

func (s *MapSession) SetStartTime(ctx context.Context, startTime time.Time) error {
	if err := s.checkState(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.startTime = startTime

	return nil
}

func (s *MapSession) SetTimeout(ctx context.Context, timeout time.Duration) error {
	if err := s.checkState(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.timeout = timeout

	return nil
}

func (s *MapSession) SetIdleTimeout(ctx context.Context, idleTimeout time.Duration) error {
	if err := s.checkState(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.idleTimeout = idleTimeout

	return nil
}

func (s *MapSession) SetLastAccessTime(ctx context.Context, lastAccessTime time.Time) error {
	if err := s.checkState(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastAccessTime = lastAccessTime

	return nil
}

func (s *MapSession) checkState(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if s.stopped.Load() == 1 {
		return ErrAlreadyStopped
	}

	return nil
}
