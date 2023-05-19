package security

import (
	"github.com/google/uuid"
	"github.com/shrinex/shield/authc"
	"strings"
	"sync/atomic"
	"time"
)

type (
	// Option can be used to customize Options
	Option func(*Options)

	// Options contains config attribute that can
	// affect how Subject manages semgt.Session(s)
	Options struct {
		// Timeout controls the maximum length of time that a
		// session is valid for before it expires
		Timeout time.Duration
		// IdleTimeout controls the maximum length of time a
		// session can be inactive before it expires
		IdleTimeout time.Duration
		// Concurrency controls the maximum active sessions
		Concurrency int
		// SamePlatformProhibited controls whether a user can be logged-in
		// a platform multiple times at the sametime
		SamePlatformProhibited bool
		// NewToken is a factory method that generates session token
		NewToken func(authc.UserDetails) string
	}

	// LoginOption can be used to customize LoginOptions
	LoginOption func(*LoginOptions)

	// LoginOptions contains config attribute that can
	// be used during login attempt
	LoginOptions struct {
		// Platform specifies the login platform
		Platform string
		// RenewToken specifies whether to generate a new token or not
		RenewToken bool
	}
)

///=====================================
///		   Global Options
///=====================================

func (opt *Options) GetTimeout() time.Duration {
	if opt.Timeout > 0 {
		return opt.Timeout
	}

	return time.Hour
}

func (opt *Options) GetIdleTimeout() time.Duration {
	if opt.IdleTimeout > 0 {
		return opt.IdleTimeout
	}

	return opt.GetTimeout()
}

func SetGlobalOptions(opts Options) {
	globalOptions.Store(&opts)
}

func GetGlobalOptions() *Options {
	return globalOptions.Load().(*Options)
}

var globalOptions = defaultGlobalOptions()

func defaultGlobalOptions() *atomic.Value {
	options := Options{
		Timeout:                12 * time.Hour,
		IdleTimeout:            time.Hour,
		Concurrency:            2,
		SamePlatformProhibited: true,
		NewToken: func(authc.UserDetails) string {
			return strings.ReplaceAll(uuid.NewString(), "-", "")
		},
	}

	v := &atomic.Value{}
	v.Store(&options)
	return v
}

///=====================================
///		   Login Options
///=====================================

var defaultLoginOptions = LoginOptions{
	Platform:   DefaultPlatform,
	RenewToken: false,
}

func WithPlatform(platform string) LoginOption {
	return func(opt *LoginOptions) {
		platform = strings.TrimSpace(platform)
		if len(platform) != 0 {
			opt.Platform = platform
		}
	}
}

func WithRenewToken() LoginOption {
	return func(opt *LoginOptions) {
		opt.RenewToken = true
	}
}
