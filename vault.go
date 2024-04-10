package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Vault struct
type Vault struct {
	password string
	vaultDir string
}

// hash the given string
func hash(s string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}

// create password file
func createPasswordFile(vaultDir string, password string) error {
	passwordFile := filepath.Join(vaultDir, ".password")
	return ioutil.WriteFile(passwordFile, []byte(hash(password)), 0400)
}

// check password
func (v *Vault) checkPassword() error {
	passwordFile := filepath.Join(v.vaultDir, ".password")
	passwordHash, err := ioutil.ReadFile(passwordFile)
	if err != nil {
		return errors.New("ErrCannotReadPasswordFile")
	}

	if hash(v.password) != string(passwordHash) {
		return errors.New("ErrInvalidPassword")
	}

	return nil
}

// NewVault creates a new Vault
func NewVault(password string) (*Vault, error) {
	// password must be 8 to 32 characters
	if len(password) < 8 || len(password) > 32 {
		return nil, errors.New("ErrInvalidPasswordLength")
	}

	// get the vault directory
	vaultDir := os.Getenv("TAPPOY_VAULT_DIR")
	if vaultDir == "" {
		vaultDir = defaultVaultDir()
	}

	// create if vault directory does not exist
	if _, err := os.Stat(vaultDir); os.IsNotExist(err) {
		err := os.MkdirAll(vaultDir, 0755)
		if err != nil {
			return nil, errors.New("ErrCannotCreateVaultDir")
		}
		err = createPasswordFile(vaultDir, password)
		if err != nil {
			return nil, errors.New("ErrCannotCreatePasswordFile")
		}
	}

	// check if vault directory is a readable and writable directory
	if stat, err := os.Stat(vaultDir); err != nil || !stat.IsDir() || stat.Mode().Perm()&0600 != 0600 {
		return nil, errors.New("ErrCannotAccessVaultDir")
	}

	v := &Vault{password, vaultDir}

	// check if password is correct
	if err := v.checkPassword(); err != nil {
		return nil, err
	}

	return v, nil
}

// make hashed key
func (v *Vault) makeHashedKey(key string) string {
	return hash(key + v.password)
}

// get password filled with spaces to 32 characters
func (v *Vault) getPassword32() string {
	return fmt.Sprintf("%-32s", v.password)
}

// Set stores the secret value in the vault
func (v *Vault) Set(key string, value string) error {
	if err := v.checkPassword(); err != nil {
		return err
	}

	// create a new file for the secret
	secretFile := filepath.Join(v.vaultDir, v.makeHashedKey(key))
	f, err := os.Create(secretFile)
	if err != nil {
		return errors.New("ErrCannotCreateSecretFile")
	}
	defer f.Close()

	block, err := aes.NewCipher([]byte(v.getPassword32()))
	if err != nil {
		return errors.New("ErrCannotCreateCipher" + err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return errors.New("ErrCannotCreateGcm")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return errors.New("ErrCannotGenerateNonce")
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	_, err = f.Write(ciphertext)
	if err != nil {
		return errors.New("ErrCannotWriteSecret")
	}

	return nil
}

// Get retrieves the secret value from the vault
func (v *Vault) Get(key string) (string, error) {
	if err := v.checkPassword(); err != nil {
		return "", err
	}

	// open the secret file
	secretFile := filepath.Join(v.vaultDir, v.makeHashedKey(key))

	// check if the secret file exists
	if _, err := os.Stat(secretFile); os.IsNotExist(err) {
		return "", errors.New("ErrVariableNotFound")
	}

	ciphertext, err := ioutil.ReadFile(secretFile)
	if err != nil {
		return "", errors.New("ErrCannotReadSecretFile")
	}

	// decrypt the secret
	block, err := aes.NewCipher([]byte(v.getPassword32()))
	if err != nil {
		return "", errors.New("ErrCannotCreateCipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("ErrCannotCreateGcm")
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ErrInvalidCiphertext")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("ErrCannotDecryptSecret")
	}

	return string(plaintext), nil
}
