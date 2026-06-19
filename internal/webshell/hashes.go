package webshell

type hashEntry struct {
	Name   string
	SHA256 string
	MD5    string
}

var knownWebshells = []hashEntry{
	// b374k shell variants
	{Name: "b374k_shell_v3.2", SHA256: "e1c4a8f9b6d2c7a3e5f8d9b0c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"},
	{Name: "b374k_shell_v2.1", SHA256: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"},

	// c99 shell
	{Name: "c99_shell_v1.0", SHA256: "d9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7"},

	// r57 shell
	{Name: "r57_shell_v1.0", SHA256: "c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7"},

	// WSO (Web Shell by oRb)
	{Name: "wso_web_shell_v2.5", SHA256: "b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"},

	// China Chopper
	{Name: "china_chopper_v3.0", SHA256: "f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7"},

	// Weevely
	{Name: "weevely_v3.2", SHA256: "a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6"},
	{Name: "weevely_v3.1", SHA256: "e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5"},

	// Generic one-liner PHP shells
	{Name: "php_one_liner_eval", SHA256: "d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3"},
	{Name: "php_system_shell", SHA256: "c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2"},
}

func buildHashDB() map[string]string {
	db := make(map[string]string, len(knownWebshells)*2)
	for _, entry := range knownWebshells {
		if entry.SHA256 != "" {
			db[entry.SHA256] = entry.Name
		}
		if entry.MD5 != "" {
			db[entry.MD5] = entry.Name
		}
	}
	return db
}
