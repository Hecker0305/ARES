package finish

import (
	"encoding/json"
	"fmt"

	"github.com/ares/engine/internal/tools"
)

func Register(r *tools.Registry) {
	r.Register("finish", func(params json.RawMessage, sc interface{}) tools.ToolResult {
		var args struct {
			Summary string `json:"summary"`
		}
		if err := json.Unmarshal(params, &args); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
		}
		return tools.ToolResult{
			Output: args.Summary,
			Done:   true,
		}
	})
}
