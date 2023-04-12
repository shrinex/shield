package security

import "errors"

const (
	kickedOutKey = "__kickedOutKey"

	PlatformKey    = "__platformKey"
	PrincipalKey   = "__principalKey"
	UserDetailsKey = "__userDetailsKey"

	DefaultPlatform = "universal"
)

var (
	ErrKickedOut = errors.New("kicked out")
)
