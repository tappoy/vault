# Package
`github.com/tappoy/vault`

# About
This golang package replaces the .env file. A single password can manage all secret variables.

# Features
- Encrypt/Decrypt variables and store them in `$TAPPOY_VAULT_DIR`. Default is `/srv/vault` for Linux and `C:\vault` for Windows.
- Variable names are hashed with password and used as file names.
- If you forget the password, you can't access the variables.

# Functions
- `NewVault(password string) (*Vault, error)`: Create a new vault.
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

# License
[LGPL-3.0](LICENSE)

# Author
[tappoy](https://github.com/tappoy)
