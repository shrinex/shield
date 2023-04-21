package semgt

import (
	"errors"
	"time"
)

var (
	nowFunc = time.Now

	// ErrExpired is returned when the session expires
	ErrExpired = errors.New("session expired")
	// ErrReplaced is returned when the session has been replaced
	ErrReplaced = errors.New("session replaced")
	// ErrOverflow is returned when the active sessions overflow
	ErrOverflow = errors.New("session overflow")
)

const (
	// AlreadyExpiredKey is a session attribute key that indicates
	// the session is expired
	AlreadyExpiredKey = "__alreadyExpiredKey"

	// AlreadyReplacedKey is a session attribute key that indicates
	// the session has been replaced
	AlreadyReplacedKey = "__alreadyReplacedKey"

	// AlreadyOverflowKey is a session attribute key that indicates
	// the logged-in sessions reaches the concurrency limit
	AlreadyOverflowKey = "__alreadyOverflowKey"
)
