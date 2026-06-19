package mythic

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ares/engine/internal/logger"
)

func (e *MythicEngine) GenerateApolloPayload(listenerName string, os string) (string, error) {
	config := map[string]interface{}{
		"payload_type": "apollo",
		"callback_host": e.config.ServerURL,
		"callback_port": 443,
		"listener":      listenerName,
		"os":            os,
	}
	return e.GeneratePayloadFromConfig("apollo", config)
}

func (e *MythicEngine) GeneratePoseidonPayload(listenerName string, os string) (string, error) {
	config := map[string]interface{}{
		"payload_type": "poseidon",
		"callback_host": e.config.ServerURL,
		"callback_port": 443,
		"listener":      listenerName,
		"os":            os,
	}
	return e.GeneratePayloadFromConfig("poseidon", config)
}

func (e *MythicEngine) GenerateAthenaPayload(listenerName string, os string) (string, error) {
	config := map[string]interface{}{
		"payload_type": "athena",
		"callback_host": e.config.ServerURL,
		"callback_port": 443,
		"listener":      listenerName,
		"os":            os,
	}
	return e.GeneratePayloadFromConfig("athena", config)
}

func (e *MythicEngine) GenerateMerlinPayload(listenerName string) (string, error) {
	config := map[string]interface{}{
		"payload_type": "merlin",
		"callback_host": e.config.ServerURL,
		"callback_port": 443,
		"listener":      listenerName,
	}
	return e.GeneratePayloadFromConfig("merlin", config)
}

func (e *MythicEngine) GeneratePayloadFromConfig(payloadType string, config map[string]interface{}) (string, error) {
	if config == nil {
		config = make(map[string]interface{})
	}
	config["payload_type"] = payloadType

	body, _ := json.Marshal(config)

	data, err := e.apiCall("POST", "/api/v1.4/payload/generate", strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("generate payload %s: %w", payloadType, err)
	}

	var resp struct {
		Status    string `json:"status"`
		PayloadID int    `json:"payload_id"`
		Message   string `json:"message"`
	}
	json.Unmarshal(data, &resp)

	result := fmt.Sprintf("[+] %s payload generated (id=%d)", payloadType, resp.PayloadID)
	logger.Info("[Mythic] " + result)

	if resp.Message != "" {
		result += "\n" + resp.Message
	}
	return result, nil
}

func (e *MythicEngine) GeneratePayloadWindows(agentType string, callbackHost string, callbackPort int) (string, error) {
	config := map[string]interface{}{
		"callback_host": callbackHost,
		"callback_port": callbackPort,
		"os":            "windows",
	}
	return e.GeneratePayloadFromConfig(agentType, config)
}

func (e *MythicEngine) GeneratePayloadLinux(agentType string, callbackHost string, callbackPort int) (string, error) {
	config := map[string]interface{}{
		"callback_host": callbackHost,
		"callback_port": callbackPort,
		"os":            "linux",
	}
	return e.GeneratePayloadFromConfig(agentType, config)
}

func (e *MythicEngine) GeneratePayloadMacOS(agentType string, callbackHost string, callbackPort int) (string, error) {
	config := map[string]interface{}{
		"callback_host": callbackHost,
		"callback_port": callbackPort,
		"os":            "macos",
	}
	return e.GeneratePayloadFromConfig(agentType, config)
}

func (e *MythicEngine) ListSupportedPayloadTypes() ([]string, error) {
	payloads, err := e.ListPayloads()
	if err != nil {
		return nil, err
	}

	types := make(map[string]bool)
	for _, p := range payloads {
		types[p.PayloadType] = true
	}

	var result []string
	for t := range types {
		result = append(result, t)
	}
	return result, nil
}

func (e *MythicEngine) RemovePayload(payloadID int) (string, error) {
	data, err := e.apiCall("DELETE", fmt.Sprintf("/api/v1.4/payload/%d", payloadID), nil)
	if err != nil {
		return "", fmt.Errorf("remove payload: %w", err)
	}

	e.mu.Lock()
	delete(e.payloads, payloadID)
	e.mu.Unlock()

	return fmt.Sprintf("[+] Payload %d removed: %s", payloadID, string(data)), nil
}

type C2ProfileConfig struct {
	ProfileName string `json:"profile_name"`
	CallbackHost string `json:"callback_host"`
	CallbackPort int    `json:"callback_port"`
	KillDate     int64  `json:"kill_date,omitempty"`
	Jitter       int    `json:"jitter,omitempty"`
}

func (e *MythicEngine) GeneratePayloadWithC2Profile(payloadType string, c2Config C2ProfileConfig) (string, error) {
	config := map[string]interface{}{
		"payload_type":  payloadType,
		"c2_profiles": []map[string]interface{}{
			{
				"name":          c2Config.ProfileName,
				"callback_host": c2Config.CallbackHost,
				"callback_port": c2Config.CallbackPort,
			},
		},
	}
	if c2Config.KillDate > 0 {
		config["kill_date"] = c2Config.KillDate
	}
	if c2Config.Jitter > 0 {
		config["jitter"] = c2Config.Jitter
	}

	return e.GeneratePayloadFromConfig(payloadType, config)
}
