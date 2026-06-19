package empire

import (
	"encoding/json"
	"net/http"
)

func (e *EmpireEngine) ListListeners() (string, error) {
	return e.doRequest(http.MethodGet, "/api/listeners", nil)
}

func (e *EmpireEngine) CreateHTTPListener(name, host, port string) (string, error) {
	body := map[string]interface{}{
		"Name":         name,
		"Host":         host,
		"Port":         port,
		"DefaultDelay": 5,
		"Jitter":       0.1,
		"KillDate":     "",
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return e.doRequest(http.MethodPost, "/api/listeners", jsonBody)
}

func (e *EmpireEngine) CreateHTTPComListener(name, host, port string) (string, error) {
	body := map[string]interface{}{
		"Name":         name,
		"Host":         host,
		"Port":         port,
		"DefaultDelay": 5,
		"Jitter":       0.1,
		"KillDate":     "",
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return e.doRequest(http.MethodPost, "/api/listeners", jsonBody)
}

func (e *EmpireEngine) CreateRedirectorListener(name, redirectTarget string) (string, error) {
	body := map[string]interface{}{
		"Name":           name,
		"RedirectTarget": redirectTarget,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return e.doRequest(http.MethodPost, "/api/listeners", jsonBody)
}

func (e *EmpireEngine) DeleteListener(name string) (string, error) {
	return e.doRequest(http.MethodDelete, "/api/listeners/"+name, nil)
}

func (e *EmpireEngine) StartListener(name string) (string, error) {
	return e.doRequest(http.MethodPost, "/api/listeners/"+name+"/start", nil)
}

func (e *EmpireEngine) StopListener(name string) (string, error) {
	return e.doRequest(http.MethodPost, "/api/listeners/"+name+"/stop", nil)
}
