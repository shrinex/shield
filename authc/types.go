package authc

import "context"

type (
	// A Token is a consolidation of an account's principals and
	// supporting credentials submitted by a user during an authentication attempt
	Token interface {
		Principal() string
		Credentials() string
	}

	// UserDetails provides core user information
	UserDetails interface {
		Principal() string
	}

	// A Realm is responsible to load UserDetails
	Realm interface {
		// Supports tests the supplied Token can be handled by this Realm
		Supports(Token) bool
		// LoadUserDetails returns an account's authentication-specific information for the specified token
		LoadUserDetails(context.Context, Token) (UserDetails, error)
	}

	// LogoutAware allowing cleanup logic to be executed during
	// logout of a previously authenticated user
	LogoutAware interface {
		// Logout triggered when a user logs out of the system
		Logout(context.Context, UserDetails)
	}

	// An Authenticator is responsible for authenticating accounts in an application
	Authenticator interface {
		// Authenticate a user based on the submitted Token
		Authenticate(context.Context, Token) (UserDetails, error)
	}
)
