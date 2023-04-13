package semgt

import (
	"errors"
	"time"
)

var (
	nowFunc = time.Now

	ErrExpired   = errors.New("session expired")
	ErrKickedOut = errors.New("kicked out")
)

const (
	AlreadyExpiredKey   = "__alreadyExpiredKey"
	AlreadyKickedOutKey = "__alreadyKickedOutKey"
)
