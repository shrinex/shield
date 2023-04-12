package semgt

import (
	"errors"
	"time"
)

var (
	nowFunc = time.Now

	ErrStopped = errors.New("session stopped")
	ErrExpired = errors.New("session expired")
)

const (
	AlreadyExpiredKey = "__alreadyExpiredKey"
)
