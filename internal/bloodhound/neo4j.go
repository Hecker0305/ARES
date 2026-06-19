package bloodhound

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

func Neo4jConnect(uri, user, password string) (string, error) {
	args := []string{
		"-s", "--connect-timeout", "10",
		"-u", fmt.Sprintf("%s:%s", user, password),
		"-H", "Accept: application/json",
		fmt.Sprintf("%s/db/data/transaction/commit", strings.TrimRight(uri, "/")),
		"-X", "POST",
		"-d", `{"statements":[{"statement":"RETURN 1 AS test"}]}`,
	}
	out, err := exec.Command("curl", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("neo4j connect failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func Neo4jRunQuery(query string) (string, error) {
	payload, err := json.Marshal(map[string]interface{}{
		"statements": []map[string]interface{}{
			{"statement": query},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal query: %w", err)
	}
	args := []string{
		"-s", "--connect-timeout", "30",
		"-H", "Content-Type: application/json",
		"-X", "POST",
		"-d", string(payload),
		"http://localhost:7474/db/data/transaction/commit",
	}
	out, err := exec.Command("curl", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("neo4j run query failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func Neo4jClearDB() (string, error) {
	return Neo4jRunQuery("MATCH (n) DETACH DELETE n")
}

func Neo4jImportData(jsonlFile string) (string, error) {
	args := []string{
		"--database", "neo4j",
		"--input", jsonlFile,
	}
	out, err := exec.Command("bloodhound-python", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("bloodhound-python import failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func Neo4jListNodes() (string, error) {
	return Neo4jRunQuery("MATCH (n) RETURN labels(n), count(n)")
}

func neo4jRunQueryWithAuth(query, uri, user, password string) (string, error) {
	payload, err := json.Marshal(map[string]interface{}{
		"statements": []map[string]interface{}{
			{"statement": query},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal query: %w", err)
	}
	args := []string{
		"-s", "--connect-timeout", "30",
		"-u", fmt.Sprintf("%s:%s", user, password),
		"-H", "Content-Type: application/json",
		"-X", "POST",
		"-d", string(payload),
		fmt.Sprintf("%s/db/data/transaction/commit", strings.TrimRight(uri, "/")),
	}
	out, err := exec.Command("curl", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("neo4j query failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

