// This golang package replaces the .env file.
// A single password can manage all secret variables.
//
// Features:
//   - Encrypt/Decrypt variables and store them in dir as binary files.
//   - Variable names are hashed with password and used as file names.
//   - If you forget the password, you can't access the variables.
//
// Dependencies:
//   - github.com/tappoy/crypto
package vault

import (
	"errors"
	"github.com/tappoy/crypto"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Vault struct
type Vault struct {
	password string
	crypto   *crypto.Crypto
	vaultDir string
}

var (
	// Cannot create the vault directory.
	ErrInvalidPasswordLength = crypto.ErrInvalidPasswordLength

	// Cannot create the vault directory.
	ErrCannotCreateVaultDir = errors.New("ErrCannotCreateVaultDir")

	// Cannot create the password file.
	ErrCannotCreatePasswordFile = errors.New("ErrCannotCreatePasswordFile")

	// Cannot access the vault directory.
	ErrCannotAccessVaultDir = errors.New("ErrCannotAccessVaultDir")

	// Cannot read the password file.
	ErrCannotReadPasswordFile = errors.New("ErrCannotReadPasswordFile")

	// Password incorrect.
	ErrPasswordIncorrect = errors.New("ErrPasswordIncorrect")

	// Cannot create the secret file.
	ErrCannotCreateSecretFile = errors.New("ErrCannotCreateSecretFile")

	// Cannot write the secret.
	ErrCannotWriteSecret = errors.New("ErrCannotWriteSecret")

	// Key not found.
	ErrKeyNotFound = errors.New("ErrKeyNotFound ")

	// Cannot read the secret file.
	ErrCannotReadSecretFile = errors.New("ErrCannotReadSecretFile")

	// Cannot delete the secret file.
	ErrCannotDeleteSecretFile = errors.New("ErrCannotDeleteSecretFile")

	// Vault is already initialized.
	ErrAlreadyInitialized = errors.New("ErrAlreadyInitialized")

	// Cannot decrypt the secret.
	ErrDecryptSecret = errors.New("ErrDecryptSecret")
)

// Create password file.
func createPasswordFile(vaultDir string, password string) error {
	passwordFile := filepath.Join(vaultDir, ".password")
	return ioutil.WriteFile(passwordFile, []byte(crypto.Hash(password)), 0440)
}

// Generate a robust password.
func GeneratePassword() string {
	return crypto.GenerateRandomString(32)
}

// Check password.
func (v *Vault) checkPassword() error {
	passwordFile := filepath.Join(v.vaultDir, ".password")
	passwordHash, err := ioutil.ReadFile(passwordFile)
	if err != nil {
		return ErrCannotReadPasswordFile
	}

	if crypto.Hash(v.password) != string(passwordHash) {
		return ErrPasswordIncorrect
	}

	return nil
}

// Create a new Vault.
// The password length is invalid. It must be 8 to 32 characters.
//
// Errors:
//   - ErrInvalidPasswordLength
func NewVault(password string, vaultDir string) (*Vault, error) {
	crypto, err := crypto.NewCrypto(password)
	if err != nil {
		return nil, ErrInvalidPasswordLength
	}

	v := &Vault{password, crypto, vaultDir}

	// check if vault is already initialized
	if v.IsInitialized() {
		// check if password is correct
		if err := v.checkPassword(); err != nil {
			return nil, err
		}
	}

	return v, nil
}

// Check if vault is already initialized.
func IsInitialized(vaultDir string) bool {
	if _, err := os.Stat(filepath.Join(vaultDir, ".password")); err == nil {
		return true
	}

	return false
}

// Check if vault is already initialized.
func (v *Vault) IsInitialized() bool {
	return IsInitialized(v.vaultDir)
}

// Init vault.
//
// Errors:
//   - ErrAlreadyInitialized
//   - ErrCannotCreateVaultDir
//   - ErrCannotAccessVaultDir
//   - ErrCannotCreatePasswordFile
func (v *Vault) Init() error {
	// check if vault is already initialized
	if IsInitialized(v.vaultDir) {
		return ErrAlreadyInitialized
	}

	// create if vault directory does not exist
	if _, err := os.Stat(v.vaultDir); os.IsNotExist(err) {
		err := os.MkdirAll(v.vaultDir, 0750)
		if err != nil {
			return ErrCannotCreateVaultDir
		}
	}

	// check if vault directory is a readable and writable directory
	if stat, err := os.Stat(v.vaultDir); err != nil || !stat.IsDir() || stat.Mode().Perm()&0750 != 0750 {
		return ErrCannotAccessVaultDir
	}

	// create password file
	err := createPasswordFile(v.vaultDir, v.password)
	if err != nil {
		return ErrCannotCreatePasswordFile
	}

	return nil
}

// Make hashed key
func (v *Vault) makeHashedKey(key string) string {
	return crypto.Hash(key + v.password)
}

// Store the secret value in the vault.
//
// Errors:
//   - ErrCannotCreateSecretFile
//   - ErrCannotWriteSecret
func (v *Vault) Set(key string, value string) error {
	if err := v.checkPassword(); err != nil {
		return err
	}

	// create a new file for the secret
	secretFile := filepath.Join(v.vaultDir, v.makeHashedKey(key))

	ciphertext := v.crypto.Encrypt([]byte(value))
	err := ioutil.WriteFile(secretFile, ciphertext, 0640)
	if err != nil {
		return ErrCannotWriteSecret
	}

	return nil
}

// Retrieve the secret value from the vault.
//
// Errors:
//   - ErrKeyNotFound
//   - crypto.ErrInvalidCiphertext
//   - crypto.ErrCannotDecryptSecret
func (v *Vault) Get(key string) (string, error) {
	if err := v.checkPassword(); err != nil {
		return "", err
	}

	// open the secret file
	secretFile := filepath.Join(v.vaultDir, v.makeHashedKey(key))

	// check if the secret file exists
	if _, err := os.Stat(secretFile); os.IsNotExist(err) {
		return "", ErrKeyNotFound
	}

	ciphertext, err := ioutil.ReadFile(secretFile)
	if err != nil {
		return "", ErrCannotReadSecretFile
	}

	plaintext, err := v.crypto.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Delete the secret value from the vault.
//
// Errors:
//   - ErrKeyNotFound
//   - ErrCannotDeleteSecretFile
func (v *Vault) Delete(key string) error {
	if err := v.checkPassword(); err != nil {
		return err
	}

	// open the secret file
	secretFile := filepath.Join(v.vaultDir, v.makeHashedKey(key))

	// check if the secret file exists
	if _, err := os.Stat(secretFile); os.IsNotExist(err) {
		return ErrKeyNotFound
	}

	// delete the secret file
	err := os.Remove(secretFile)
	if err != nil {
		return ErrCannotDeleteSecretFile
	}

	return nil
}
