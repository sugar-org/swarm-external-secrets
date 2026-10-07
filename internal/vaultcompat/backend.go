package vaultcompat

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	openbaoapi "github.com/openbao/openbao/api/v2"
	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/utils"
	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat/login"
	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat/vclient"
)

const (
	minRenewalDelay     = time.Second
	renewalRetryWait    = 5 * time.Second
	renewalRetryMaxWait = time.Minute
)

type Backend struct {
	client      vclient.Client
	config      Config
	loginMethod login.Method

	authMu sync.Mutex
	auth   *vclient.Auth

	renewCtx    context.Context
	renewCancel context.CancelFunc
	renewWG     sync.WaitGroup
	newTimer    func() renewalTimer
}

type renewalTimer interface {
	C() <-chan time.Time
	Reset(time.Duration) bool
	Stop() bool
}

type timeRenewalTimer struct {
	timer *time.Timer
}

func newStoppedRenewalTimer() renewalTimer {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	return &timeRenewalTimer{timer: timer}
}

func (t *timeRenewalTimer) C() <-chan time.Time {
	return t.timer.C
}

func (t *timeRenewalTimer) Reset(delay time.Duration) bool {
	return t.timer.Reset(delay)
}

func (t *timeRenewalTimer) Stop() bool {
	return t.timer.Stop()
}

func New(cfg Config) (*Backend, error) {
	client, err := newClient(cfg)
	if err != nil {
		return nil, err
	}

	loginMethod, err := newLoginMethod(cfg)
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	auth, err := authenticate(context.Background(), client, loginMethod, cfg)
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	renewCtx, renewCancel := context.WithCancel(context.Background())
	backend := &Backend{
		client:      client,
		config:      cfg,
		loginMethod: loginMethod,
		auth:        auth,
		renewCtx:    renewCtx,
		renewCancel: renewCancel,
		newTimer:    newStoppedRenewalTimer,
	}
	backend.startTokenRenewal()
	log.Printf("Successfully initialized %s provider using %s method", cfg.ProviderName, cfg.AuthMethod)
	return backend, nil
}

func (b *Backend) GetSecret(ctx context.Context, secretInfo *utils.SecretInfo) ([]byte, error) {
	log.Debugf("Reading secret from %s path: %s", b.config.ProviderName, secretInfo.SecretPath)

	secret, err := b.client.Read(ctx, secretInfo.SecretPath)
	if err != nil && b.canReauthenticate() && vclient.IsAuthError(err) {
		log.Warnf("Read from %s failed with auth error, re-authenticating", b.config.ProviderName)
		if authErr := b.reauthenticate(ctx); authErr != nil {
			return nil, fmt.Errorf("failed to re-authenticate with %s: %w", b.config.ProviderName, authErr)
		}
		secret, err = b.client.Read(ctx, secretInfo.SecretPath)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from %s: %w", b.config.ProviderName, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("secret not found at path: %s", secretInfo.SecretPath)
	}

	value, err := utils.ExtractSecretValueFromKVWithVersion(secret.Data, secretInfo.SecretField, b.config.KVVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %w", err)
	}

	log.Debugf("Successfully retrieved secret from %s", b.config.ProviderName)
	return value, nil
}

func (b *Backend) Close() error {
	if b.renewCancel != nil {
		b.renewCancel()
	}
	b.renewWG.Wait()

	if b.client == nil {
		return nil
	}
	return b.client.Close()
}

func newClient(cfg Config) (vclient.Client, error) {
	tlsCfg := vclient.TLSConfig{
		CACert:     cfg.CACert,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
		SkipVerify: cfg.SkipVerify,
	}

	switch cfg.ProviderName {
	case "openbao":
		apiConfig := openbaoapi.DefaultConfig()
		apiConfig.Address = cfg.Address
		if err := vclient.ConfigureOpenBaoTLS(apiConfig, tlsCfg); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}

		client, err := openbaoapi.NewClient(apiConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create openbao client: %w", err)
		}

		return vclient.NewOpenBao(client), nil
	default:
		apiConfig := vaultapi.DefaultConfig()
		apiConfig.Address = cfg.Address
		if err := vclient.ConfigureHashiVaultTLS(apiConfig, tlsCfg); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}

		client, err := vaultapi.NewClient(apiConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create vault client: %w", err)
		}

		return vclient.NewHashiVault(client), nil
	}
}

func newLoginMethod(cfg Config) (login.Method, error) {
	loginCfg, err := cfg.loginConfig()
	if err != nil {
		return nil, err
	}

	return login.New(login.Config{
		Method:          loginCfg.Method,
		Token:           loginCfg.Token,
		RoleID:          loginCfg.RoleID,
		SecretID:        loginCfg.SecretID,
		AppRoleAuthPath: loginCfg.AppRoleAuthPath,
		JWTRole:         loginCfg.JWTRole,
		JWTAuthPath:     loginCfg.JWTAuthPath,
		JWTSource:       loginCfg.JWTSource,
	})
}

func authenticate(
	ctx context.Context,
	client vclient.Client,
	method login.Method,
	cfg Config,
) (*vclient.Auth, error) {
	result, err := method.Login(ctx, client)
	if err != nil {
		switch cfg.AuthMethod {
		case "approle":
			return nil, fmt.Errorf("approle authentication failed: %w", err)
		case "jwt":
			return nil, fmt.Errorf("jwt authentication failed: %w", err)
		default:
			return nil, err
		}
	}

	if result == nil || result.ClientToken == "" {
		switch cfg.AuthMethod {
		case "approle":
			return nil, fmt.Errorf("no auth info returned from approle login")
		case "jwt":
			return nil, fmt.Errorf("no auth info returned from jwt login")
		default:
			return nil, fmt.Errorf("authentication returned no client token")
		}
	}

	client.SetToken(result.ClientToken)
	return cloneAuth(result), nil
}

func (b *Backend) startTokenRenewal() {
	if !b.canRenewAuth() {
		return
	}
	if b.renewCtx == nil || b.renewCancel == nil {
		b.renewCtx, b.renewCancel = context.WithCancel(context.Background())
	}
	if b.newTimer == nil {
		b.newTimer = newStoppedRenewalTimer
	}

	b.renewWG.Add(1)
	go b.renewLoop()
}

func (b *Backend) renewLoop() {
	defer b.renewWG.Done()

	timer := b.newTimer()
	defer timer.Stop()

	for {
		delay, ok := b.nextRenewDelay()
		if !ok {
			return
		}
		if !b.waitForRenewal(timer, delay) {
			return
		}

		retryWait := renewalRetryWait
		for {
			if err := b.renewOrReauthenticate(b.renewCtx); err != nil {
				log.Warnf("Failed to renew %s token: %v", b.config.ProviderName, err)
				if !b.waitForRenewal(timer, retryDelayWithJitter(retryWait)) {
					return
				}
				retryWait = nextRetryWait(retryWait)
				continue
			}
			break
		}
	}
}

func nextRetryWait(current time.Duration) time.Duration {
	next := current * 2
	if next > renewalRetryMaxWait {
		return renewalRetryMaxWait
	}
	return next
}

func retryDelayWithJitter(base time.Duration) time.Duration {
	jitterLimit := base / 2
	if jitterLimit <= 0 {
		return base
	}

	jitter, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(jitterLimit)))
	if err != nil {
		return base
	}

	return base + time.Duration(jitter.Int64())
}

func (b *Backend) waitForRenewal(timer renewalTimer, delay time.Duration) bool {
	timer.Reset(delay)

	select {
	case <-b.renewCtx.Done():
		timer.Stop()
		return false
	case <-timer.C():
		return true
	}
}

func (b *Backend) renewOrReauthenticate(ctx context.Context) error {
	b.authMu.Lock()
	defer b.authMu.Unlock()

	renewed, err := b.client.RenewSelf(ctx, 0)
	if err == nil && renewed != nil {
		b.updateRenewedAuthLocked(renewed)
		log.Debugf("Successfully renewed %s token", b.config.ProviderName)
		return nil
	}

	if err == nil {
		err = fmt.Errorf("renew response did not include auth info")
	}
	log.Warnf("Renewing %s token failed, attempting re-authentication: %v", b.config.ProviderName, err)
	if authErr := b.reauthenticateLocked(ctx); authErr != nil {
		return fmt.Errorf("renew self failed: %v; re-authentication failed: %w", err, authErr)
	}

	return nil
}

func (b *Backend) reauthenticate(ctx context.Context) error {
	b.authMu.Lock()
	defer b.authMu.Unlock()

	return b.reauthenticateLocked(ctx)
}

func (b *Backend) reauthenticateLocked(ctx context.Context) error {
	auth, err := authenticate(ctx, b.client, b.loginMethod, b.config)
	if err != nil {
		return err
	}

	b.auth = auth
	log.Debugf("Successfully re-authenticated with %s", b.config.ProviderName)
	return nil
}

func (b *Backend) updateRenewedAuthLocked(renewed *vclient.Auth) {
	next := cloneAuth(b.auth)
	if next == nil {
		next = &vclient.Auth{}
	}

	if renewed.ClientToken != "" {
		b.client.SetToken(renewed.ClientToken)
		next.ClientToken = renewed.ClientToken
	}
	next.Renewable = renewed.Renewable
	next.LeaseTTL = renewed.LeaseTTL
	b.auth = next
}

func (b *Backend) canRenewAuth() bool {
	if !b.canReauthenticate() {
		return false
	}

	b.authMu.Lock()
	defer b.authMu.Unlock()

	return b.auth != nil && b.auth.Renewable && b.auth.LeaseTTL > 0
}

func (b *Backend) canReauthenticate() bool {
	switch b.config.AuthMethod {
	case "approle", "jwt":
		return b.loginMethod != nil
	default:
		return false
	}
}

func (b *Backend) nextRenewDelay() (time.Duration, bool) {
	b.authMu.Lock()
	defer b.authMu.Unlock()

	if b.auth == nil || !b.auth.Renewable || b.auth.LeaseTTL <= 0 {
		return 0, false
	}

	delay := time.Duration(b.auth.LeaseTTL) * time.Second * 2 / 3
	if delay < minRenewalDelay {
		delay = minRenewalDelay
	}

	return delay, true
}

func cloneAuth(auth *vclient.Auth) *vclient.Auth {
	if auth == nil {
		return nil
	}

	return &vclient.Auth{
		ClientToken: auth.ClientToken,
		Renewable:   auth.Renewable,
		LeaseTTL:    auth.LeaseTTL,
	}
}
