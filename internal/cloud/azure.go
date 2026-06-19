package cloud

import (
	"fmt"
	"os/exec"
	"strings"
)

func runAZ(args ...string) (string, error) {
	cmd := exec.Command("az", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("az command failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func (e *CloudEngine) AzureLogin(username, password string) (string, error) {
	return runAZ("login", "--username", username, "--password", password)
}

func (e *CloudEngine) AzureLoginServicePrincipal(tenant, appId, secret string) (string, error) {
	return runAZ("login", "--service-principal", "--tenant", tenant, "-u", appId, "-p", secret)
}

func (e *CloudEngine) AzureListVMs() (string, error) {
	return runAZ("vm", "list")
}

func (e *CloudEngine) AzureListStorageAccounts() (string, error) {
	return runAZ("storage", "account", "list")
}

func (e *CloudEngine) AzureListStorageContainers(account string) (string, error) {
	return runAZ("storage", "container", "list", "--account-name", account)
}

func (e *CloudEngine) AzureListKeyVaults() (string, error) {
	return runAZ("keyvault", "list")
}

func (e *CloudEngine) AzureListSecrets(vaultName string) (string, error) {
	return runAZ("keyvault", "secret", "list", "--vault-name", vaultName)
}

func (e *CloudEngine) AzureGetSecret(vaultName, secretName string) (string, error) {
	return runAZ("keyvault", "secret", "show", "--vault-name", vaultName, "--name", secretName)
}

func (e *CloudEngine) AzureListRoleAssignments() (string, error) {
	return runAZ("role", "assignment", "list")
}

func (e *CloudEngine) AzureListUsers() (string, error) {
	return runAZ("ad", "user", "list")
}

func (e *CloudEngine) AzureListGroups() (string, error) {
	return runAZ("ad", "group", "list")
}

func (e *CloudEngine) AzureListServicePrincipals() (string, error) {
	return runAZ("ad", "sp", "list")
}

func (e *CloudEngine) AzureCreateUser(username, password string) (string, error) {
	return runAZ("ad", "user", "create", "--display-name", username, "--user-principal-name", username, "--password", password)
}

func (e *CloudEngine) AzureAddRoleAssignment(user, role string) (string, error) {
	return runAZ("role", "assignment", "create", "--assignee", user, "--role", role)
}

func (e *CloudEngine) AzureRunCommand(vmName, resourceGroup, command string) (string, error) {
	return runAZ("vm", "run-command", "invoke", "--name", vmName, "--resource-group", resourceGroup, "--command-id", "RunShellScript", "--scripts", command)
}

func (e *CloudEngine) AzureExportKeyVault(vaultName string) (string, error) {
	return runAZ("keyvault", "secret", "list", "--vault-name", vaultName, "--query", "[].{name:name,value:value}")
}

func (e *CloudEngine) AzureMetadataQuery(path string) (string, error) {
	cmd := exec.Command("curl", "-s", "-H", "Metadata:true", fmt.Sprintf("http://169.254.169.254/metadata/instance/%s?api-version=2021-02-01", path))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Azure metadata query failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}
