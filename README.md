# Package
`github.com/tappoy/vault`

# About
This golang package replaces the .env file. A single password can manage all secret variables.

# Features
- Encrypt/Decrypt variables and store them in dir as binary files.
- Variable names are hashed with password and used as file names.
- If you forget the password, you can't access the variables.

# Functions
- `NewVault(password string, vaultDir string) (*Vault, error)`: Create a new vault.
- `(*Vault) Init() error`: Initialize the vault dir. If already initialized, return ErrAlreadyInitialized.
- `(*Vault) IsInitialized() bool`: Check if the vault is initialized.
- `(*Vault) Set(key string, value string) error`: Set a variable.
- `(*Vault) Get(key string) (string, error)`: Get a variable.

# Errors
- `ErrInvalidPasswordLength`: The password length is invalid. It must be 8 to 32 characters.
- `ErrCannotCreateVaultDir`: Cannot create the vault directory.
- `ErrCannotCreatePasswordFile`: Cannot create the password file.
- `ErrCannotAccessVaultDir`: Cannot access the vault directory.
- `ErrVariableNotFound`: The variable is not found.
- `ErrInvalidPassword`: The password is invalid.
- `ErrCannotCreateSecretFile`: Cannot create the secret file.
- `ErrCannotCreateCipher`: Cannot create the cipher.
- `ErrCannotCreateGcm`: Cannot create the GCM.
- `ErrCannotGenerateNonce`: Cannot generate the nonce.
- `ErrCannotWriteSecret`: Cannot write the secret.
- `ErrCannotReadSecretFile`: Cannot read the secret file.
- `ErrInvalidCiphertext`: The ciphertext is invalid.
- `ErrCannotDecryptSecret`: Cannot decrypt the secret.
- `ErrAlreadyInitialized`: The vault is already initialized.

# LICENSE
This package is licensed under the LGPL-3.0 license. For more information, see the LICENSE file.

# AUTHOR
[tappoy](https://github.com/tappoy)
