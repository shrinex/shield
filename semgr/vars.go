package semgr

import (
	"errors"
	"time"
)

var (
	nowFunc = time.Now

	ErrAlreadyStopped = errors.New("session already stopped")
	ErrAlreadyExpired = errors.New("session already expired")
)
