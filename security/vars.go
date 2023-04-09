package security

import "errors"

const (
	PlatformKey    = "__platformKey"
	KickedOutKey   = "__kickedOutKey"
	PrincipalKey   = "__principalKey"
	UserDetailsKey = "__userDetailsKey"

	DefaultPlatform = "universal"
)

var (
	ErrKickedOut = errors.New("kicked out")
)
