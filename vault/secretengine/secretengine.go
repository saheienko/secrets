package secretengine

import "fmt"

// SecretEngine is a wrapper over vault secret engines.
type SecretEngine interface {
	String() string
	GetSecret(key SecretKey, keyContext map[string]string) (map[string]interface{}, error)
	PutSecret(key SecretKey, secretData map[string]interface{}, keyContext map[string]string) error
	DeleteSecret(key SecretKey, keyContext map[string]string) error
	ListSecrets() ([]string, error)
}

// SecretKey contains parameters used to identify the vault secret.
type SecretKey struct {
	// Name is a secret name, used to build a url (example, /transit/keys/:name).
	Name string
	// Namespace is a vault namespace, optional.
	Namespace string
}

// String returns a string representation of the SecretKey.
func (k SecretKey) String() string {
	return fmt.Sprintf("namespace=%s, secretID=%s", k.Namespace, k.Name)
}