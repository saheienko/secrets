package kv

import (
	"github.com/hashicorp/vault/api"
	"github.com/libopenstorage/secrets/vault/secretengine"
)

var _ secretengine.SecretEngine = vaultKV{}

type vaultKV struct {
	client *api.Logical
}

func (v vaultKV) String() string {
	panic("implement me")
}

func (v vaultKV) GetSecret(key secretengine.SecretKey, keyContext map[string]string) (map[string]interface{}, error) {
	panic("implement me")
}

func (v vaultKV) PutSecret(key secretengine.SecretKey, secretData map[string]interface{}, keyContext map[string]string) error {
	panic("implement me")
}

func (v vaultKV) DeleteSecret(key secretengine.SecretKey, keyContext map[string]string) error {
	panic("implement me")
}

func (v vaultKV) ListSecrets() ([]string, error) {
	panic("implement me")
}

