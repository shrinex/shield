package semgt

import (
	"context"
	"github.com/shrinex/shield/codec"
	"sync"
	"time"
)

type (
	// Session provides a way to identify a user in an agnostic way
	Session interface {
		// Token is a unique string that identifies the Session
		Token() string
		// StartTime returns the creation time
		StartTime(context.Context) (time.Time, error)
		// Timeout controls the maximum length of time that a
		// session is valid for before it expires
		Timeout(context.Context) (time.Duration, error)
		// IdleTimeout controls the maximum length of time a
		// session can be inactive before it expires
		IdleTimeout(context.Context) (time.Duration, error)
		// LastAccessTime returns the last time this Session was accessed
		LastAccessTime(context.Context) (time.Time, error)
		// Attribute gets the Object associated with the specified key
		Attribute(context.Context, string, any) (bool, error)
		AttributeAsInt(context.Context, string) (int64, bool, error)
		AttributeAsBool(context.Context, string) (bool, bool, error)
		AttributeAsFloat(context.Context, string) (float64, bool, error)
		AttributeAsString(context.Context, string) (string, bool, error)
		// SetAttribute sets the attribute value for the provided attribute key
		SetAttribute(context.Context, string, any) error
		// AttributeKeys returns the attribute keys that have a value associated with it
		AttributeKeys(context.Context) ([]string, error)
		// RemoveAttribute Removes the attribute with the provided attribute key
		RemoveAttribute(context.Context, string) error
		// Expired returns true if the session is expired
		Expired(context.Context) (bool, error)
		// Touch sets the last accessed time
		Touch(context.Context) error
		// Flush ensures the Session is saved
		Flush(context.Context) error
		// Stop expires this session
		Stop(context.Context) error
	}

	// MapSession is a Session implementation that is backed by a map
	MapSession struct {
		token          string
		mu             sync.RWMutex
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

func NewSessionTimeout(token string, codec codec.Codec,
	timeout time.Duration, idleTimeout time.Duration) *MapSession {
	nowTime := nowFunc()
	return &MapSession{
		token:          token,
		codec:          codec,
		startTime:      nowTime,
		lastAccessTime: nowTime,
		timeout:        timeout,
		idleTimeout:    idleTimeout,
		attrs:          make(map[string]string),
	}
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

	return s.GetExpired(), nil
}

func (s *MapSession) Attribute(ctx context.Context, key string, ptr any) (bool, error) {
	if err := s.checkState(ctx); err != nil {
		return false, err
	}

	s.mu.RLock()
	data, ok := s.attrs[key]
	s.mu.RUnlock()

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
	var value int64
	found, err := s.Attribute(ctx, key, &value)
	if err != nil {
		return 0, false, err
	}

	return value, found, nil
}

func (s *MapSession) AttributeAsBool(ctx context.Context, key string) (bool, bool, error) {
	var value bool
	found, err := s.Attribute(ctx, key, &value)
	if err != nil {
		return false, false, err
	}

	return value, found, nil
}

func (s *MapSession) AttributeAsFloat(ctx context.Context, key string) (float64, bool, error) {
	var value float64
	found, err := s.Attribute(ctx, key, &value)
	if err != nil {
		return 0, false, err
	}

	return value, found, nil
}

func (s *MapSession) AttributeAsString(ctx context.Context, key string) (string, bool, error) {
	var value string
	found, err := s.Attribute(ctx, key, &value)
	if err != nil {
		return "", false, err
	}

	return value, found, nil
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

	if value == nil {
		s.mu.Lock()
		delete(s.attrs, key)
		s.mu.Unlock()
		return nil
	}

	data, err := s.codec.Encode(value)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.attrs[key] = data
	s.mu.Unlock()

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
	if err := s.checkState(ctx); err != nil {
		return err
	}

	s.SetLastAccessTime(nowFunc())

	return nil
}

func (s *MapSession) Flush(ctx context.Context) error {
	if err := s.checkState(ctx); err != nil {
		return err
	}

	// no-op
	return nil
}

func (s *MapSession) Stop(ctx context.Context) error {
	return s.SetAttribute(ctx, AlreadyExpiredKey, true)
}

///=====================================
///		    Getters & Setters
///=====================================

func (s *MapSession) SetStartTime(startTime time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.startTime = startTime
}

func (s *MapSession) GetStartTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.startTime
}

func (s *MapSession) SetTimeout(timeout time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.timeout = timeout
}

func (s *MapSession) GetTimeout() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.timeout
}

func (s *MapSession) SetIdleTimeout(idleTimeout time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.idleTimeout = idleTimeout
}

func (s *MapSession) GetIdleTimeout() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.idleTimeout
}

func (s *MapSession) SetLastAccessTime(lastAccessTime time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastAccessTime = lastAccessTime
}

func (s *MapSession) GetLastAccessTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.lastAccessTime
}

func (s *MapSession) GetExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.attrs[AlreadyExpiredKey]; ok {
		return true
	}

	nowTime := nowFunc()
	timedOut := s.startTime.Add(s.timeout).Before(nowTime)
	inactive := s.lastAccessTime.Add(s.idleTimeout).Before(nowTime)

	return timedOut || inactive
}

func (s *MapSession) RawAttribute(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	value, ok := s.attrs[key]
	return value, ok
}

func (s *MapSession) SetRawAttribute(key string, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(value) == 0 {
		delete(s.attrs, key)
	} else {
		s.attrs[key] = value
	}
}

func (s *MapSession) checkState(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.attrs[AlreadyReplacedKey]; ok {
		return ErrReplaced
	}

	if _, ok := s.attrs[AlreadyOverflowKey]; ok {
		return ErrOverflow
	}

	if _, ok := s.attrs[AlreadyExpiredKey]; ok {
		return ErrExpired
	}

	return nil
}
