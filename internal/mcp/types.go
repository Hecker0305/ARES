package mcp

type IntegrationType int

const (
	BurpSuite IntegrationType = iota
	Caido
	HackerOne
	Nuclei
	Nmap
)

func (t IntegrationType) String() string {
	switch t {
	case BurpSuite:
		return "burpsuite"
	case Caido:
		return "caido"
	case HackerOne:
		return "hackerone"
	case Nuclei:
		return "nuclei"
	case Nmap:
		return "nmap"
	default:
		return "unknown"
	}
}

type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema ToolInputSchema `json:"inputSchema"`
}

type ToolInputSchema struct {
	Type       string                  `json:"type"`
	Properties map[string]ToolProperty `json:"properties"`
	Required   []string                `json:"required,omitempty"`
}

type ToolProperty struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type McpServer struct {
	Name         string           `json:"name"`
	Version      string           `json:"version"`
	Tools        []ToolDefinition `json:"tools"`
	integrations []IntegrationType
}

func NewMcpServer(name, version string) *McpServer {
	return &McpServer{
		Name:    name,
		Version: version,
	}
}

func (s *McpServer) RegisterIntegration(t IntegrationType) {
	for _, it := range s.integrations {
		if it == t {
			return
		}
	}
	s.integrations = append(s.integrations, t)
}

func (s *McpServer) ListIntegrations() []IntegrationType {
	result := make([]IntegrationType, len(s.integrations))
	copy(result, s.integrations)
	return result
}

func (s *McpServer) RegisterTool(t ToolDefinition) {
	s.Tools = append(s.Tools, t)
}

func (s *McpServer) GetTool(name string) *ToolDefinition {
	for _, t := range s.Tools {
		if t.Name == name {
			return &t
		}
	}
	return nil
}

type McpConfig struct {
	BurpRESTAPI    string `json:"burp_rest_api"`
	BurpAPIKey     string `json:"burp_api_key"`
	CaidoGraphQL   string `json:"caido_graphql"`
	CaidoAPIKey    string `json:"caido_api_key"`
	HackerOneAPI   string `json:"hackerone_api"`
	HackerOneToken string `json:"hackerone_token"`
	HackerOneUser  string `json:"hackerone_username"`
	NucleiPath     string `json:"nuclei_path"`
	TemplatesPath  string `json:"nuclei_templates"`
	NmapPath       string `json:"nmap_path"`
}
