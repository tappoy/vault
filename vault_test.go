package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// TAPPY_VAULT_DIR for testing
var testDir = "tmp/vault_test"

// test password
var testPassword = "test1234"

// test main
func TestMain(m *testing.M) {
	m.Run()
}

// before test, set TAPPOY_VAULT_DIR to a temp directory then run given function finally remove the temp directory
func withVault(t *testing.T, f func(t *testing.T)) {
	os.RemoveAll(testDir)
	f(t)
}

// test incorrect password all edge cases
func TestVaultIncorrectPassword(t *testing.T) {
	// test 32 length password
	withVault(t, func(t *testing.T) {
		_, err := NewVault("12345678901234567890123456789012", testDir)
		if err != nil {
			t.Errorf("Error password length 32 %v", err)
		}
	})

	// test 33 length password
	withVault(t, func(t *testing.T) {
		_, err := NewVault("123456789012345678901234567890123", testDir)
		if err == nil {
			t.Error("Error password length 33")
		}
	})

	// test 8 length password
	withVault(t, func(t *testing.T) {
		_, err := NewVault("12345678", testDir)
		if err != nil {
			t.Error("Error password length 8")
		}
	})

	// test 7 length password
	withVault(t, func(t *testing.T) {
		_, err := NewVault("1234567", testDir)
		if err == nil {
			t.Error("Error password length 7")
		}
	})

}

// test vault default dir
func TestVaultDefualtDir(t *testing.T) {
	v, err := NewVault(testPassword, testDir)
	if err != nil {
		t.Errorf("Error creating vault %v", err)
		t.FailNow()
	}

	err = v.Init()
	if err != nil {
		t.Errorf("Error initializing vault %v", err)
		t.FailNow()
	}

	if v.vaultDir != testDir {
		t.Error("Error creating vault")
	}

	// check if the password file exists
	passwordFile := filepath.Join(testDir, ".password")
	if _, err := os.Stat(passwordFile); os.IsNotExist(err) {
		t.Errorf("Error creating password file %v", err)
	}

	// check if the password is correct
	err = v.checkPassword()
	if err != nil {
		t.Errorf("Error checking password %v", err)
	}

	// test set function
	err = v.Set("key", "value")
	if err != nil {
		t.Errorf("Error setting value %v", err)
	}

	// test get function
	value, err := v.Get("key")
	if err != nil {
		t.Errorf("Error getting value %v", err)
	}

	if value != "value" {
		t.Errorf("Error getting value changed %v", value)
	}

	// make vault with wrong password
	_, err = NewVault("wrongpassword", testDir)
	if err == nil {
		t.Errorf("Error creating vault with wrong password %v", err)
	} else if err != ErrPasswordIncorrect {
		t.Errorf("Error wrong error message %v", err)
	}

	// remove the temp directory
	os.RemoveAll(testDir)
}

// test init vault
func TestVaultInit(t *testing.T) {
	// remove the temp directory
	os.RemoveAll(testDir)

	// check if already initialized
	if IsInitialized(testDir) {
		t.Errorf("Error already initialized")
	}

	v, err := NewVault(testPassword, testDir)
	if err != nil {
		t.Errorf("Error creating vault %v", err)
		t.FailNow()
	}

	// check if already initialized
	if v.IsInitialized() {
		t.Errorf("Error already initialized")
	}

	// init vault
	err = v.Init()
	if err != nil {
		t.Errorf("Error initializing vault %v", err)
		t.FailNow()
	}

	// check if already initialized
	if !v.IsInitialized() {
		t.Errorf("Error not initialized")
	}

	// check if the password file exists
	passwordFile := filepath.Join(testDir, ".password")
	if _, err := os.Stat(passwordFile); os.IsNotExist(err) {
		t.Errorf("Error creating password file %v", err)
	}

	// check if already initialized
	err = v.Init()
	if err != ErrAlreadyInitialized {
		t.Errorf("Error already initialized %v", err)
	}

	// set value
	err = v.Set("key", "value")
	if err != nil {
		t.Errorf("Error setting value %v", err)
	}

	// get value
	value, err := v.Get("key")
	if err != nil {
		t.Errorf("Error getting value %v", err)
	}

	if value != "value" {
		t.Errorf("Error getting value changed %v", value)
	}

}

func TestVaultDeleteValue(t *testing.T) {
	// remove the temp directory
	os.RemoveAll(testDir)

	v, err := NewVault(testPassword, testDir)
	if err != nil {
		t.Errorf("Error creating vault %v", err)
		t.FailNow()
	}

	// init vault
	err = v.Init()
	if err != nil {
		t.Errorf("Error initializing vault %v", err)
		t.FailNow()
	}

	// set value
	err = v.Set("key", "value")
	if err != nil {
		t.Errorf("Error setting value %v", err)
	}

	// get value
	value, err := v.Get("key")
	if err != nil {
		t.Errorf("Error getting value %v", err)
	}

	if value != "value" {
		t.Errorf("Error getting value changed %v", value)
	}

	// delete value
	err = v.Delete("key")
	if err != nil {
		t.Errorf("Error deleting value %v", err)
	}

	// get value
	_, err = v.Get("key")
	if err != ErrKeyNotFound {
		t.Errorf("Error key not found %v", err)
	}

	// delete value
	err = v.Delete("key")
	if err != ErrKeyNotFound {
		t.Errorf("Error key not found %v", err)
	}

}

func TestGeneratePassword(t *testing.T) {
	// Just print 10 passwords.
	for i := 0; i < 10; i++ {
		password := GeneratePassword()
		t.Logf("Password: %v", password)
	}
}
