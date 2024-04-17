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

// Errors
var (
  ErrInvalidPasswordLength = errors.New("ErrInvalidPasswordLength")
  ErrCannotCreateVaultDir = errors.New("ErrCannotCreateVaultDir")
  ErrCannotCreatePasswordFile = errors.New("ErrCannotCreatePasswordFile")
  ErrCannotAccessVaultDir = errors.New("ErrCannotAccessVaultDir")
  ErrCannotReadPasswordFile = errors.New("ErrCannotReadPasswordFile")
  ErrInvalidPassword = errors.New("ErrInvalidPassword")
  ErrCannotCreateSecretFile = errors.New("ErrCannotCreateSecretFile")
  ErrCannotCreateCipher = errors.New("ErrCannotCreateCipher")
  ErrCannotCreateGcm = errors.New("ErrCannotCreateGcm")
  ErrCannotGenerateNonce = errors.New("ErrCannotGenerateNonce")
  ErrCannotWriteSecret = errors.New("ErrCannotWriteSecret")
  ErrVariableNotFound = errors.New("ErrVariableNotFound")
  ErrCannotReadSecretFile = errors.New("ErrCannotReadSecretFile")
  ErrInvalidCiphertext = errors.New("ErrInvalidCiphertext")
  ErrCannotDecryptSecret = errors.New("ErrCannotDecryptSecret")
)

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
		return ErrCannotReadPasswordFile
	}

	if hash(v.password) != string(passwordHash) {
		return ErrInvalidPassword
	}

	return nil
}

// NewVault creates a new Vault
func NewVault(password string, vaultDir string) (*Vault, error) {
	// password must be 8 to 32 characters
	if len(password) < 8 || len(password) > 32 {
		return nil, ErrInvalidPasswordLength
	}

	// create if vault directory does not exist
	if _, err := os.Stat(vaultDir); os.IsNotExist(err) {
		err := os.MkdirAll(vaultDir, 0755)
		if err != nil {
			return nil, ErrCannotCreateVaultDir
		}
	}

  // create if password file does not exist
  if _, err := os.Stat(filepath.Join(vaultDir, ".password")); err != nil {
    err := createPasswordFile(vaultDir, password)
    if err != nil {
      return nil, ErrCannotCreatePasswordFile
    }
  }

	// check if vault directory is a readable and writable directory
	if stat, err := os.Stat(vaultDir); err != nil || !stat.IsDir() || stat.Mode().Perm()&0600 != 0600 {
		return nil, ErrCannotAccessVaultDir
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
		return ErrCannotCreateSecretFile
	}
	defer f.Close()

	block, err := aes.NewCipher([]byte(v.getPassword32()))
	if err != nil {
		return ErrCannotCreateCipher
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ErrCannotCreateGcm
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return ErrCannotGenerateNonce
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	_, err = f.Write(ciphertext)
	if err != nil {
		return ErrCannotWriteSecret
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
		return "", ErrVariableNotFound
	}

	ciphertext, err := ioutil.ReadFile(secretFile)
	if err != nil {
		return "", ErrCannotReadSecretFile
	}

	// decrypt the secret
	block, err := aes.NewCipher([]byte(v.getPassword32()))
	if err != nil {
		return "", ErrCannotCreateCipher
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrCannotCreateGcm
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", ErrInvalidCiphertext
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrCannotDecryptSecret
	}

	return string(plaintext), nil
}
