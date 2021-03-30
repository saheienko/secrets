package kv2

import (
	"github.com/hashicorp/vault/api"
	"github.com/libopenstorage/secrets/vault/secretengine"
)

var _ secretengine.SecretEngine = vaultKV2{}

type vaultKV2 struct {
	client *api.Logical
}

func (v vaultKV2) String() string {
	panic("implement me")
}

func (v vaultKV2) GetSecret(key secretengine.SecretKey, keyContext map[string]string) (map[string]interface{}, error) {
	panic("implement me")
}

func (v vaultKV2) PutSecret(key secretengine.SecretKey, secretData map[string]interface{}, keyContext map[string]string) error {
	panic("implement me")
}

func (v vaultKV2) DeleteSecret(key secretengine.SecretKey, keyContext map[string]string) error {
	panic("implement me")
}

func (v vaultKV2) ListSecrets() ([]string, error) {
	panic("implement me")
}

