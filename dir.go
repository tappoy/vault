// go:build !windows

package vault

func defaultVaultDir() string {
	return "/srv/vault"
}
