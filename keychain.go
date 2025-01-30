package ecr

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/google/go-containerregistry/pkg/authn"
)

// ecrKeychain implements the authn.Keychain interface.
type ecrKeychain struct {
	cfg         aws.Config
	cache       map[string]authn.Authenticator
	cacheMu     sync.RWMutex
	earlyExpiry time.Duration
}

// Resolve returns an authn.Authenticator instance for the given registry or authn.Anonymous if not an ECR URL.
func (keychain *ecrKeychain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	reg := Parse(resource.RegistryStr())
	if reg == nil {
		return authn.Anonymous, nil
	}
	key := reg.DNSSuffix + "/" + reg.Region + "/" + strconv.FormatBool(reg.FIPS)
	keychain.cacheMu.RLock()
	if auth, ok := keychain.cache[key]; ok {
		keychain.cacheMu.RUnlock()
		return auth, nil
	}
	keychain.cacheMu.RUnlock()
	var auth authn.Authenticator
	if reg.DNSSuffix == ecrPublicDomain {
		auth = NewPublicAuthenticatorWithEarlyExpiry(ecrpublic.NewFromConfig(keychain.cfg, func(opts *ecrpublic.Options) {
			opts.Region = reg.Region
		}), keychain.earlyExpiry)
	} else {
		auth = NewAuthenticatorWithEarlyExpiry(ecr.NewFromConfig(keychain.cfg, func(opts *ecr.Options) {
			opts.Region = reg.Region
			if reg.FIPS {
				opts.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateEnabled
			}
		}), keychain.earlyExpiry)
	}
	keychain.cacheMu.Lock()
	defer keychain.cacheMu.Unlock()
	if auth, ok := keychain.cache[key]; ok {
		return auth, nil
	}
	keychain.cache[key] = auth
	return auth, nil
}

// NewKeychainWithEarlyExpiry returns a new Keychain instance with a custom earlyExpiry value.
func NewKeychainWithEarlyExpiry(cfg aws.Config, earlyExpiry time.Duration) authn.Keychain {
	return &ecrKeychain{
		cfg:         cfg,
		cache:       make(map[string]authn.Authenticator),
		earlyExpiry: earlyExpiry,
	}
}

// NewKeychain returns a new Keychain instance that uses the provided AWS configuration.
func NewKeychain(cfg aws.Config) authn.Keychain {
	return NewKeychainWithEarlyExpiry(cfg, DefaultEarlyExpiry)
}

// DefaultKeychain uses the default AWS credentials chain.
func DefaultKeychain(ctx context.Context) (authn.Keychain, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return NewKeychain(cfg), nil
}

// MustDefaultKeychain is like DefaultKeychain but panics on error.
func MustDefaultKeychain(ctx context.Context) authn.Keychain {
	keychain, err := DefaultKeychain(ctx)
	if err != nil {
		panic(err)
	}
	return keychain
}
