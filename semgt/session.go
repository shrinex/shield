package semgt

import (
	"context"
	"github.com/shrinex/shield/codec"
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
		Attribute(context.Context, string, any) (bool, error)
		AttributeAsInt(context.Context, string) (int64, bool, error)
		AttributeAsBool(context.Context, string) (bool, bool, error)
		AttributeAsFloat(context.Context, string) (float64, bool, error)
		AttributeAsString(context.Context, string) (string, bool, error)
		SetAttribute(context.Context, string, any) error
		AttributeKeys(context.Context) ([]string, error)
		RemoveAttribute(context.Context, string) error
		Expired(context.Context) (bool, error)
		Touch(context.Context) error
		Stop(context.Context) error
	}

	MapSession struct {
		token          string
		mu             sync.RWMutex
		stopped        int32
		startTime      time.Time
		lastAccessTime time.Time
		codec          codec.Codec
		timeout        time.Duration
		idleTimeout    time.Duration
		attrs          map[string]string
	}
)

var _ Session = (*MapSession)(nil)

func NewSession(token string, codec codec.Codec) *MapSession {
	nowTime := nowFunc()
	return &MapSession{
		token:          token,
		codec:          codec,
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

func (s *MapSession) Attribute(ctx context.Context, key string, ptr any) (bool, error) {
	if err := s.checkState(ctx); err != nil {
		return false, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	data, ok := s.attrs[key]
	if !ok {
		return false, nil
	}

	err := s.codec.Decode(data, ptr)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (s *MapSession) AttributeAsInt(ctx context.Context, key string) (int64, bool, error) {
	var result int64
	found, err := s.Attribute(ctx, key, &result)
	if err != nil {
		return 0, false, err
	}

	return result, found, nil
}

func (s *MapSession) AttributeAsBool(ctx context.Context, key string) (bool, bool, error) {
	var result bool
	found, err := s.Attribute(ctx, key, &result)
	if err != nil {
		return false, false, err
	}

	return result, found, nil
}

func (s *MapSession) AttributeAsFloat(ctx context.Context, key string) (float64, bool, error) {
	var result float64
	found, err := s.Attribute(ctx, key, &result)
	if err != nil {
		return 0, false, err
	}

	return result, found, nil
}

func (s *MapSession) AttributeAsString(ctx context.Context, key string) (string, bool, error) {
	var result string
	found, err := s.Attribute(ctx, key, &result)
	if err != nil {
		return "", false, err
	}

	return result, found, nil
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

func (s *MapSession) SetAttribute(ctx context.Context, key string, value any) error {
	if err := s.checkState(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if value == nil {
		delete(s.attrs, key)
		return nil
	}

	data, err := s.codec.Encode(value)
	if err != nil {
		return err
	}

	s.attrs[key] = data
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

	atomic.StoreInt32(&s.stopped, 1)

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

	if atomic.LoadInt32(&s.stopped) == 1 {
		return ErrAlreadyStopped
	}

	return nil
}
