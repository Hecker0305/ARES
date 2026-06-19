package empire

import (
	"encoding/json"
	"net/http"
)

func (e *EmpireEngine) ListStagers() (string, error) {
	return e.doRequest(http.MethodGet, "/api/stagers", nil)
}

func (e *EmpireEngine) GenerateDLLStager(listenerName string) (string, error) {
	body := map[string]string{
		"Listener": listenerName,
		"Language": "dll",
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return e.doRequest(http.MethodPost, "/api/stagers", jsonBody)
}

func (e *EmpireEngine) GenerateLauncherBat(listenerName string) (string, error) {
	body := map[string]string{
		"Listener": listenerName,
		"Language": "bat",
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return e.doRequest(http.MethodPost, "/api/stagers", jsonBody)
}

func (e *EmpireEngine) GenerateLauncherPS1(listenerName string) (string, error) {
	body := map[string]string{
		"Listener": listenerName,
		"Language": "powershell",
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return e.doRequest(http.MethodPost, "/api/stagers", jsonBody)
}

func (e *EmpireEngine) GenerateMacroStager(listenerName string) (string, error) {
	body := map[string]string{
		"Listener": listenerName,
		"Language": "macro",
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return e.doRequest(http.MethodPost, "/api/stagers", jsonBody)
}

func (e *EmpireEngine) GenerateShellcodeStager(listenerName string) (string, error) {
	body := map[string]string{
		"Listener": listenerName,
		"Language": "shellcode",
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return e.doRequest(http.MethodPost, "/api/stagers", jsonBody)
}

func (e *EmpireEngine) GenerateCSharpStager(listenerName string) (string, error) {
	body := map[string]string{
		"Listener": listenerName,
		"Language": "csharp",
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return e.doRequest(http.MethodPost, "/api/stagers", jsonBody)
}
