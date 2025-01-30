package ecr

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/google/go-containerregistry/pkg/authn"
)

// DefaultEarlyExpiry is used by NewAuthenticator when earlyExpiry is unspecified
var DefaultEarlyExpiry = 15 * time.Minute

type funcGetAuthorizationToken func(ctx context.Context) (token *string, expiry *time.Time, err error)

// cachedAuthConfig is an authn.AuthConfig with an expiry time.
type cachedAuthConfig struct {
	AuthConfig *authn.AuthConfig
	ExpiresAt  time.Time
}

// ecrAuthenticator implements an authn.Authenticator that can authenticate to ECR.
// It caches the authorization token until it expires reducing the round-trips to ECR.
type ecrAuthenticator struct {
	earlyExpiry time.Duration
	gat         funcGetAuthorizationToken
	cache       atomic.Pointer[cachedAuthConfig]
}

func (authenticator *ecrAuthenticator) Authorization() (*authn.AuthConfig, error) {
	// Check if we have a cached token already and it hasn't expired.
	if cached := authenticator.cache.Load(); cached != nil && time.Now().Before(cached.ExpiresAt) {
		return cached.AuthConfig, nil
	}

	// Fetch a new token from ECR.
	token, expiry, err := authenticator.gat(context.TODO())
	if err != nil {
		return nil, err
	}

	// Decode the token and extract the username and password just once
	tokenBytes, err := base64.StdEncoding.DecodeString(aws.ToString(token))
	if err != nil {
		return nil, fmt.Errorf("(*ecr.Client).GetAuthorizationToken returned an invalid token: %w", err)
	}
	username, password, ok := strings.Cut(string(tokenBytes), ":")
	if !ok {
		return nil, errors.New("(*ecr.Client).GetAuthorizationToken returned an invalid token: missing ':'")
	}
	authConfig := &authn.AuthConfig{Username: username, Password: password}

	// Cache the result and return it.
	authenticator.cache.Store(&cachedAuthConfig{
		AuthConfig: authConfig,
		ExpiresAt:  aws.ToTime(expiry).Add(-authenticator.earlyExpiry),
	})
	return authConfig, nil
}

// NewAuthenticatorWithEarlyExpiry returns a new Authenticator instance with a custom earlyExpiry value.
func NewAuthenticatorWithEarlyExpiry(client *ecr.Client, earlyExpiry time.Duration) authn.Authenticator {
	return &ecrAuthenticator{gat: func(ctx context.Context) (token *string, expiresAt *time.Time, err error) {
		out, err := client.GetAuthorizationToken(context.TODO(), &ecr.GetAuthorizationTokenInput{})
		if err != nil {
			return nil, nil, fmt.Errorf("(*ecr.Client).GetAuthorizationToken failed: %w", err)
		} else if len(out.AuthorizationData) == 0 || out.AuthorizationData[0].AuthorizationToken == nil {
			return nil, nil, errors.New("(*ecr.Client).GetAuthorizationToken returned no authorization data")
		}
		return out.AuthorizationData[0].AuthorizationToken, out.AuthorizationData[0].ExpiresAt, nil
	}}
}

// NewAuthenticator returns a new Authenticator instance from the given ECR client.
func NewAuthenticator(client *ecr.Client) authn.Authenticator {
	return NewAuthenticatorWithEarlyExpiry(client, DefaultEarlyExpiry)
}

// NewPublicAuthenticatorWithEarlyExpiry returns a new Authenticator instance with a custom earlyExpiry value.
func NewPublicAuthenticatorWithEarlyExpiry(client *ecrpublic.Client, earlyExpiry time.Duration) authn.Authenticator {
	return &ecrAuthenticator{gat: func(ctx context.Context) (token *string, expiresAt *time.Time, err error) {
		out, err := client.GetAuthorizationToken(context.TODO(), &ecrpublic.GetAuthorizationTokenInput{})
		if err != nil {
			return nil, nil, fmt.Errorf("(*ecrpublic.Client).GetAuthorizationToken failed: %w", err)
		} else if out.AuthorizationData.AuthorizationToken == nil {
			return nil, nil, errors.New("(*ecrpublic.Client).GetAuthorizationToken returned no authorization data")
		}
		return out.AuthorizationData.AuthorizationToken, out.AuthorizationData.ExpiresAt, nil
	}}
}

// NewPublicAuthenticator returns a new Authenticator instance from the given ECR client.
func NewPublicAuthenticator(client *ecrpublic.Client) authn.Authenticator {
	return NewPublicAuthenticatorWithEarlyExpiry(client, DefaultEarlyExpiry)
}
