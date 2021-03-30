package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
	"github.com/hashicorp/vault/command/agent/auth/kubernetes"
	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/vault/secretengine"
)

const (
	Name                = secrets.TypeVault
	DefaultBackendPath  = "secret/"
	VaultBackendPathKey = "VAULT_BACKEND_PATH"
	VaultBackendKey     = "VAULT_BACKEND"
	vaultAddressPrefix  = "http"
	kvVersionKey        = "version"
	kvDataKey           = "data"
	kvVersion1          = "kv"
	kvVersion2          = "kv-v2"

	AuthMethodKubernetes = "kubernetes"

	// AuthMethod is a vault authentication method used.
	// https://www.vaultproject.io/docs/auth#auth-methods
	AuthMethod = "VAULT_AUTH_METHOD"
	// AuthMountPath defines a custom auth mount path.
	AuthMountPath = "VAULT_AUTH_MOUNT_PATH"
	// AuthKubernetesRole is the role to authenticate against on Vault.
	AuthKubernetesRole = "VAULT_AUTH_KUBERNETES_ROLE"
	// AuthKubernetesTokenPath is the file path to a custom JWT token to use for authentication.
	// If omitted, the default service account token path is used.
	AuthKubernetesTokenPath = "VAULT_AUTH_KUBERNETES_TOKEN_PATH"

	// AuthKubernetesMountPath
	AuthKubernetesMountPath = "kubernetes"

	SecretEngineKV      = "kv"
	SecretEngineKV2     = "kv-v2"
	SecretEngineTransit = "transit"
)

var (
	ErrVaultTokenNotSet    = errors.New("VAULT_TOKEN not set.")
	ErrVaultAddressNotSet  = errors.New("VAULT_ADDR not set.")
	ErrInvalidVaultToken   = errors.New("VAULT_TOKEN is invalid")
	ErrInvalidSkipVerify   = errors.New("VAULT_SKIP_VERIFY is invalid")
	ErrInvalidVaultAddress = errors.New("VAULT_ADDRESS is invalid. " +
		"Should be of the form http(s)://<ip>:<port>")

	ErrAuthMethodUnknown = fmt.Errorf("unknown auth method")
	ErrKubernetesRole    = fmt.Errorf("%s not set", AuthKubernetesRole)
)

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}

type vaultSecrets struct {
	mu     sync.RWMutex
	client *api.Client

	lockClientToken  sync.Mutex
	currentNamespace string

	endpoint      string
	backendPath   string
	namespace     string
	isKvBackendV2 bool
	autoAuth      bool
	config        map[string]interface{}
	secretEngine  secretengine.SecretEngine
}

// These variables are helpful in testing to stub method call from packages
var (
	newVaultClient = api.NewClient
	isKvV2         = isKvBackendV2
)

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	// DefaultConfig uses the environment variables if present.
	config := api.DefaultConfig()

	if len(secretConfig) == 0 && config.Error != nil {
		return nil, config.Error
	}

	address := getVaultParam(secretConfig, api.EnvVaultAddress)
	if address == "" {
		return nil, ErrVaultAddressNotSet
	}
	// Vault fails if address is not in correct format
	if !strings.HasPrefix(address, vaultAddressPrefix) {
		return nil, ErrInvalidVaultAddress
	}
	config.Address = address

	if err := configureTLS(config, secretConfig); err != nil {
		return nil, err
	}

	client, err := newVaultClient(config)
	if err != nil {
		return nil, err
	}

	namespace := getVaultParam(secretConfig, api.EnvVaultNamespace)
	if len(namespace) > 0 {
		// use a namespace as a header for setup purposes
		// later use it as a key prefix
		client.SetNamespace(namespace)
		defer client.SetNamespace("")
	}

	var autoAuth bool
	var token string
	if getVaultParam(secretConfig, AuthMethod) != "" {
		token, err = getAuthToken(client, secretConfig)
		if err != nil {
			closeIdleConnections(config)
			return nil, err
		}

		autoAuth = true
	} else {
		token = getVaultParam(secretConfig, api.EnvVaultToken)
	}
	if token == "" {
		closeIdleConnections(config)
		return nil, ErrVaultTokenNotSet
	}
	client.SetToken(token)

	backendPath := getVaultParam(secretConfig, VaultBackendPathKey)
	if backendPath == "" {
		backendPath = DefaultBackendPath
	}

	var isBackendV2 bool
	backend := getVaultParam(secretConfig, VaultBackendKey)
	if backend == kvVersion1 {
		isBackendV2 = false
	} else if backend == kvVersion2 {
		isBackendV2 = true
	} else {
		// TODO: Handle backends other than kv
		isBackendV2, err = isKvV2(client, backendPath)
		if err != nil {
			closeIdleConnections(config)
			return nil, err
		}
	}
	return &vaultSecrets{
		endpoint:         config.Address,
		namespace:        namespace,
		currentNamespace: namespace,
		client:           client,
		backendPath:      backendPath,
		isKvBackendV2:    isBackendV2,
		autoAuth:         autoAuth,
		config:           secretConfig,
		secretEngine:     secretengine.NewSecretEngine(client),
	}, nil
}

func (v *vaultSecrets) String() string {
	return Name
}

func (v *vaultSecrets) GetSecret(
	secretID string,
	keyContext map[string]string,
) (map[string]interface{}, error) {
	key := v.keyPath(secretID, keyContext)
	secretData, err := v.getSecret(key, keyContext)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %s: %s", key, err)
	}
	if secretData == nil {
		return nil, secrets.ErrInvalidSecretId
	}

	if v.isKvBackendV2 {
		if data, exists := secretData[kvDataKey]; exists && data != nil {
			if data, ok := data.(map[string]interface{}); ok {
				return data, nil
			}
		}
		return nil, secrets.ErrInvalidSecretId
	}

	return secretData, nil
}

func (v *vaultSecrets) PutSecret(
	secretID string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	if v.isKvBackendV2 {
		secretData = map[string]interface{}{
			kvDataKey: secretData,
		}
	}

	key := v.keyPath(secretID, keyContext)
	if err := v.write(key, secretData, keyContext); err != nil {
		return fmt.Errorf("failed to put secret: %s: %s", key, err)
	}
	return nil
}

func (v *vaultSecrets) DeleteSecret(
	secretID string,
	keyContext map[string]string,
) error {
	key := v.keyPath(secretID, keyContext)
	if err := v.delete(key, keyContext); err != nil {
		return fmt.Errorf("failed to delete secret: %s: %s", key, err)
	}
	return nil
}

func (v *vaultSecrets) Encrypt(
	secretID string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *vaultSecrets) Decrypt(
	secretID string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *vaultSecrets) Rencrypt(
	originalSecretID string,
	newSecretID string,
	originalKeyContext map[string]string,
	newKeyContext map[string]string,
	encryptedData string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *vaultSecrets) ListSecrets() ([]string, error) {
	return nil, secrets.ErrNotSupported
}

func (v *vaultSecrets) keyPath(secretID string, keyContext map[string]string) secretengine.SecretKey {
	namespace := v.namespace
	if keyContext != nil && len(keyContext[secrets.KeyVaultNamespace]) > 0 {
		namespace = keyContext[secrets.KeyVaultNamespace]
	}
	return secretengine.SecretKey{
		Name:      secretID,
		Namespace: namespace,
	}
}

func (v *vaultSecrets) getSecret(key secretengine.SecretKey, keyContext map[string]string) (map[string]interface{}, error) {
	if v.autoAuth {
		v.lockClientToken.Lock()
		defer v.lockClientToken.Unlock()

		if err := v.setNamespaceToken(key.Namespace); err != nil {
			return nil, err
		}
	}

	secretValue, err := v.lockedGetSecret(key, keyContext)
	if v.isTokenExpired(err) {
		if err = v.renewToken(key.Namespace); err != nil {
			return nil, fmt.Errorf("failed to renew token: %s", err)
		}
		return v.lockedGetSecret(key, keyContext)
	}
	return secretValue, err
}

func (v *vaultSecrets) write(key secretengine.SecretKey, data map[string]interface{}, keyContext map[string]string) error {
	if v.autoAuth {
		v.lockClientToken.Lock()
		defer v.lockClientToken.Unlock()

		if err := v.setNamespaceToken(key.Namespace); err != nil {
			return err
		}
	}

	err := v.lockedPutSecret(key, data, keyContext)
	if v.isTokenExpired(err) {
		if err = v.renewToken(key.Namespace); err != nil {
			return fmt.Errorf("failed to renew token: %s", err)
		}
		return v.lockedPutSecret(key, data, keyContext)
	}
	return err
}

func (v *vaultSecrets) delete(key secretengine.SecretKey, keyContext map[string]string) error {
	if v.autoAuth {
		v.lockClientToken.Lock()
		defer v.lockClientToken.Unlock()

		if err := v.setNamespaceToken(key.Namespace); err != nil {
			return err
		}
	}

	err := v.lockedDeleteSecret(key, keyContext)
	if v.isTokenExpired(err) {
		if err = v.renewToken(key.Namespace); err != nil {
			return fmt.Errorf("failed to renew token: %s", err)
		}
		return v.lockedDeleteSecret(key, keyContext)
	}
	return err
}

func (v *vaultSecrets) lockedGetSecret(key secretengine.SecretKey, keyContext map[string]string) (map[string]interface{}, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.secretEngine.GetSecret(key, keyContext)
}

func (v *vaultSecrets) lockedPutSecret(key secretengine.SecretKey, data map[string]interface{}, keyContext map[string]string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.secretEngine.PutSecret(key, data, keyContext)
}

func (v *vaultSecrets) lockedDeleteSecret(key secretengine.SecretKey, keyContext map[string]string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.secretEngine.DeleteSecret(key, keyContext)
}

func (v *vaultSecrets) renewToken(namespace string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(namespace) > 0 {
		v.client.SetNamespace(namespace)
		defer v.client.SetNamespace("")
	}
	token, err := getAuthToken(v.client, v.config)
	if err != nil {
		return fmt.Errorf("get auth token for %s namespace: %s", namespace, err)
	}

	v.currentNamespace = namespace
	v.client.SetToken(token)
	return nil
}

func (v *vaultSecrets) isTokenExpired(err error) bool {
	return err != nil && v.autoAuth && strings.Contains(err.Error(), "permission denied")
}

// setNamespaceToken  is used for a multi-token support with a kubernetes auto auth setup.
//
// This allows to talk with a multiple vault namespaces (which are not sub-namespace). Create
// the same “Kubernetes Auth Role” in each of the configured namespace. For every request it
// fetches the token for that specific namespace.
func (v *vaultSecrets) setNamespaceToken(namespace string) error {
	if v.currentNamespace == namespace {
		return nil
	}

	return v.renewToken(namespace)
}

func isKvBackendV2(client *api.Client, backendPath string) (bool, error) {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return false, err
	}

	for path, mount := range mounts {
		// path is represented as 'path/'
		if trimSlash(path) == trimSlash(backendPath) {
			version := mount.Options[kvVersionKey]
			if version == "2" {
				return true, nil
			}
			return false, nil
		}
	}

	return false, fmt.Errorf("Secrets engine with mount path '%s' not found",
		backendPath)
}

func getVaultParam(secretConfig map[string]interface{}, name string) string {
	if tokenIntf, exists := secretConfig[name]; exists {
		tokenStr, ok := tokenIntf.(string)
		if !ok {
			return ""
		}
		return strings.TrimSpace(tokenStr)
	} else {
		return strings.TrimSpace(os.Getenv(name))
	}
}

func configureTLS(config *api.Config, secretConfig map[string]interface{}) error {
	tlsConfig := api.TLSConfig{}
	skipVerify := getVaultParam(secretConfig, api.EnvVaultInsecure)
	if skipVerify != "" {
		insecure, err := strconv.ParseBool(skipVerify)
		if err != nil {
			return ErrInvalidSkipVerify
		}
		tlsConfig.Insecure = insecure
	}

	cacert := getVaultParam(secretConfig, api.EnvVaultCACert)
	tlsConfig.CACert = cacert

	capath := getVaultParam(secretConfig, api.EnvVaultCAPath)
	tlsConfig.CAPath = capath

	clientcert := getVaultParam(secretConfig, api.EnvVaultClientCert)
	tlsConfig.ClientCert = clientcert

	clientkey := getVaultParam(secretConfig, api.EnvVaultClientKey)
	tlsConfig.ClientKey = clientkey

	tlsserverName := getVaultParam(secretConfig, api.EnvVaultTLSServerName)
	tlsConfig.TLSServerName = tlsserverName

	return config.ConfigureTLS(&tlsConfig)
}

func getAuthToken(client *api.Client, config map[string]interface{}) (string, error) {
	path, _, data, err := authenticate(client, config)
	if err != nil {
		return "", err
	}

	secret, err := client.Logical().Write(path, data)
	if err != nil {
		return "", err
	}
	if secret == nil || secret.Auth == nil {
		return "", errors.New("authentication returned nil auth info")
	}
	if secret.Auth.ClientToken == "" {
		return "", errors.New("authentication returned empty client token")
	}

	return secret.Auth.ClientToken, err
}

func authenticate(client *api.Client, config map[string]interface{}) (string, http.Header, map[string]interface{}, error) {
	method := getVaultParam(config, AuthMethod)
	switch method {
	case AuthMethodKubernetes:
		return authKubernetes(client, config)
	}
	return "", nil, nil, fmt.Errorf("%s method: %s", method, ErrAuthMethodUnknown)
}

func authKubernetes(client *api.Client, config map[string]interface{}) (string, http.Header, map[string]interface{}, error) {
	authConfig, err := buildAuthConfig(config)
	if err != nil {
		return "", nil, nil, err
	}
	method, err := kubernetes.NewKubernetesAuthMethod(authConfig)
	if err != nil {
		return "", nil, nil, err
	}

	return method.Authenticate(context.TODO(), client)
}

func buildAuthConfig(config map[string]interface{}) (*auth.AuthConfig, error) {
	role := getVaultParam(config, AuthKubernetesRole)
	if role == "" {
		return nil, ErrKubernetesRole
	}
	mountPath := getVaultParam(config, AuthMountPath)
	if mountPath == "" {
		mountPath = AuthKubernetesMountPath
	}
	tokenPath := getVaultParam(config, AuthKubernetesTokenPath)

	authMountPath := path.Join("auth", mountPath)
	return &auth.AuthConfig{
		Logger:    hclog.NewNullLogger(),
		MountPath: authMountPath,
		Config: map[string]interface{}{
			"role":       role,
			"token_path": tokenPath,
		},
	}, nil
}

func trimSlash(in string) string {
	return strings.Trim(in, "/")
}

type keyPath struct {
	backendPath string
	isBackendV2 bool
	namespace   string
	secretID    string
}

func (k keyPath) Namespace() string {
	return k.namespace
}

func (k keyPath) String() string {
	return fmt.Sprintf("backendPath=%s, backendV2=%t, namespace=%s, secretID=%s", k.backendPath, k.isBackendV2, k.namespace, k.secretID)
}

func (k keyPath) Path() string {
	if k.isBackendV2 {
		return path.Join(k.namespace, k.backendPath, kvDataKey, k.secretID)
	}
	return path.Join(k.namespace, k.backendPath, k.secretID)
}

func closeIdleConnections(cfg *api.Config) {
	if cfg == nil || cfg.HttpClient == nil {
		return
	}
	// close connection in case of error (a fix for go version < 1.12)
	if tp, ok := cfg.HttpClient.Transport.(*http.Transport); ok {
		tp.CloseIdleConnections()
	}
}
