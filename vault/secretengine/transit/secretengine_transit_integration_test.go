package transit
//
//import (
//	"encoding/base64"
//	"encoding/json"
//	"github.com/libopenstorage/secrets/vault"
//	"os"
//	"path"
//	"testing"
//
//	"github.com/hashicorp/vault/api"
//	"github.com/libopenstorage/secrets"
//	"github.com/libopenstorage/secrets/pkg/store"
//	"github.com/stretchr/testify/require"
//)
//
//// TestVaultTransit runs an e2e test for vault transit secret engine implementation.
//// Use VAULT_ADDR and VAULT_TOKEN environment variables to setup the vault client.
//func TestVaultTransit(t *testing.T) {
//	// set VAULT_ADDR env variable for a custom vault endpoint
//	vaultClient, err := api.NewClient(api.DefaultConfig())
//	if err != nil {
//		t.Fatal(err)
//	}
//	token := os.Getenv("VAULT_TOKEN")
//	if token == "" {
//		t.Fatal("vault token should be set")
//	}
//	vaultClient.SetToken(os.Getenv("VAULT_TOKEN"))
//
//	// setup
//	ps := store.NewFilePersistenceStore()
//	testBasePath := "/tmp/test-vault-transit"
//	ps.SetBasePath(testBasePath)
//	se := vaultTransit{
//		ps:     ps,
//		client: vaultClient.Logical(),
//	}
//
//	secretID := "testsecret"
//	secretKey := vault.keyPath{secretID: secretID}
//
//	// run test
//	err = se.Write(secretKey, nil, nil)
//	require.Equal(t, secrets.ErrNotSupported, err)
//
//	genSupported := se.IsSupportGeneration()
//	require.Equal(t, true, genSupported)
//
//	err = se.CreateSecret(secretKey, nil)
//	require.Nil(t, err)
//
//	err = se.CreateSecret(secretKey, nil)
//	require.Nil(t, err)
//
//	// try to get and decrypt it manually
//	encryptedSecret, err := ps.GetPublic(path.Join("vault", secretKey.secretID))
//	require.Nil(t, err)
//
//	vaultSecret, err := vaultClient.Logical().Write(
//		path.Join("transit/decrypt", secretKey.secretID),
//		map[string]interface{}{"ciphertext": string(encryptedSecret)},
//	)
//	require.Nil(t, err)
//
//	encodedSecret, ok := vaultSecret.Data["plaintext"].(string)
//	require.Equal(t, true, ok)
//
//	decodedPassphrase, err := base64.StdEncoding.DecodeString(encodedSecret)
//	require.Nil(t, err)
//
//	expectedSecretData := make(map[string]interface{})
//	err = json.Unmarshal(decodedPassphrase, &expectedSecretData)
//	require.Nil(t, err)
//
//	// read secret data
//	secretData, err := se.Read(secretKey)
//	require.Nilf(t, err, "write secret data to a store: %s", err)
//	require.Equal(t, expectedSecretData, secretData)
//
//	// delete secret data
//	err = se.Delete(secretKey)
//	require.Nil(t, err)
//
//	// ensure vault encryption key and persistence store data have been removed
//	found, err := ps.Exists(se.persistentStorePath(secretKey))
//	require.Nil(t, err)
//	require.Equal(t, false, found)
//
//	// TODO:
//	//secretData, err = se.Read(secretKey)
//	//require.Equal(t, notFoundErr, err)
//	//require.Nil(t, secretData)
//
//	// clear test data
//	err = os.RemoveAll(testBasePath)
//	require.Nil(t, err)
//}
