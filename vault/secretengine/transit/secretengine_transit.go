package transit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"

	"github.com/hashicorp/vault/api"
	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/pkg/store"
	"github.com/libopenstorage/secrets/vault/client/transit"
	"github.com/libopenstorage/secrets/vault/secretengine"
)

var _ secretengine.SecretEngine = vaultTransit{}

func New(client *api.Logical, ps store.PersistenceStore) (*vaultTransit, error) {
	transitClient, err := transit.New(client)
	if err != nil {
		return nil, err
	}
	if ps == nil {
		return nil, fmt.Errorf("persistence store should be set")
	}
	return &vaultTransit{
		client: transitClient,
		ps:     ps,
	}, nil
}

type vaultTransit struct {
	client *transit.VaultTransit
	ps     store.PersistenceStore
}

func (v vaultTransit) String() string {
	return "vault-transit"
}

func (v vaultTransit) GetSecret(key secretengine.SecretKey, keyContext map[string]string) (map[string]interface{}, error) {
	_, customData := keyContext[secrets.CustomSecretData]
	_, publicData := keyContext[secrets.PublicSecretData]
	if customData && publicData {
		return nil, &secrets.ErrInvalidKeyContext{
			Reason: "both CustomSecretData and PublicSecretData flags cannot be set",
		}
	}

	dek, err := v.getDekFromStore(key)
	if err != nil {
		return nil, err
	}

	secretData := make(map[string]interface{})
	if publicData {
		secretData[key.Name] = dek
		return secretData, nil
	}

	// Use the CRK to unwrap the DEK and get the secret passphrase
	encodedPassphrase, err := v.client.Decrypt(toTransitKey(key), string(dek))
	if err != nil {
		return nil, err
	}
	decodedPassphrase, err := base64.StdEncoding.DecodeString(encodedPassphrase)
	if err != nil {
		return nil, err
	}
	if customData {
		if err := json.Unmarshal(decodedPassphrase, &secretData); err != nil {
			return nil, err
		}
	} else {
		secretData[key.Name] = string(decodedPassphrase)
	}
	return secretData, nil
}

func (v vaultTransit) PutSecret(key secretengine.SecretKey, secretData map[string]interface{}, keyContext map[string]string) error {
	var (
		cipher string
		err    error
	)

	_, override := keyContext[secrets.OverwriteSecretDataInStore]
	_, customData := keyContext[secrets.CustomSecretData]
	_, publicData := keyContext[secrets.PublicSecretData]

	if err := secrets.KeyContextChecks(keyContext, secretData); err != nil {
		return err
	} else if publicData && len(secretData) > 0 {
		publicDek, ok := secretData[key.Name]
		if !ok {
			return secrets.ErrInvalidSecretData
		}
		dek, ok := publicDek.([]byte)
		if !ok {
			return &secrets.ErrInvalidKeyContext{
				Reason: "secret data when PublicSecretData flag is set should be of the type []byte",
			}
		}
		cipher = string(dek)

	} else if len(secretData) > 0 && customData {
		// Wrap the custom secret data and create a new entry in store
		// with the input secretID and the returned dek
		value, err := json.Marshal(secretData)
		if err != nil {
			return err
		}
		encodedPassphrase := base64.StdEncoding.EncodeToString(value)
		cipher, err = v.client.Encrypt(toTransitKey(key), encodedPassphrase)
	} else {
		// Generate a new dek and create a new entry in store
		// with the input secretID and the generated dek
		cipher, err = v.client.GenerateDataKey(toTransitKey(key))
	}
	if err != nil {
		return err
	}
	return v.ps.Set(
		v.persistentStorePath(key),
		[]byte(cipher),
		nil,
		nil,
		override,
	)
}

func (v vaultTransit) DeleteSecret(key secretengine.SecretKey, keyContext map[string]string) error {
	// TODO: delete from vault?

	return v.ps.Delete(v.persistentStorePath(key))
}

func (v vaultTransit) Encrypt(secretId string, plaintTextData string, keyContext map[string]string) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v vaultTransit) Decrypt(secretId string, encryptedData string, keyContext map[string]string) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v vaultTransit) Rencrypt(originalSecretId string, newSecretId string, originalKeyContext map[string]string, newKeyContext map[string]string, encryptedData string) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v vaultTransit) ListSecrets() ([]string, error) {
	return v.ps.List()
}

func (v vaultTransit) getDekFromStore(key secretengine.SecretKey) ([]byte, error) {
	secretPath := v.persistentStorePath(key)
	if exists, err := v.ps.Exists(secretPath); err != nil {
		return nil, err
	} else if !exists {
		return nil, secrets.ErrInvalidSecretId
	}

	// Get the DEK (Data Encryption Key) from kvdb
	return v.ps.GetPublic(secretPath)
}

func (v vaultTransit) persistentStorePath(key secretengine.SecretKey) string {
	return path.Join("vault", key.Namespace, key.Name)
}

func toTransitKey(key secretengine.SecretKey) transit.SecretKey {
	return transit.SecretKey{
		Name:      key.Name,
		Namespace: key.Namespace,
	}
}
