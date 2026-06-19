package commands

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ares/engine/internal/logger"
)

type CommandCategory int

const (
	CategoryRecon      CommandCategory = iota
	CategoryHunt       CommandCategory = iota
	CategoryValidation CommandCategory = iota
	CategoryReport     CommandCategory = iota
	CategorySession    CommandCategory = iota
	CategoryUtility    CommandCategory = iota
	CategoryWeb3       CommandCategory = iota
)

func (c CommandCategory) String() string {
	switch c {
	case CategoryRecon:
		return "Recon"
	case CategoryHunt:
		return "Hunt"
	case CategoryValidation:
		return "Validation"
	case CategoryReport:
		return "Report"
	case CategorySession:
		return "Session"
	case CategoryUtility:
		return "Utility"
	case CategoryWeb3:
		return "Web3"
	default:
		return "Unknown"
	}
}

var DefaultRegistry = NewRegistry()

type Handler func(args []string) string

type Command struct {
	Name        string
	Description string
	Usage       string
	Handler     Handler
	Category    CommandCategory
	Aliases     []string
}

type Registry struct {
	mu       sync.RWMutex
	commands map[string]*Command
	aliases  map[string]string
}

func NewRegistry() *Registry {
	return &Registry{
		commands: make(map[string]*Command),
		aliases:  make(map[string]string),
	}
}

func (r *Registry) Register(cmd *Command) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.commands[cmd.Name] = cmd
	for _, alias := range cmd.Aliases {
		r.aliases[alias] = cmd.Name
	}
	logger.Debug("Command registered", logger.Fields{"name": cmd.Name, "category": cmd.Category.String()})
}

func (r *Registry) Dispatch(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return "No command provided. Type /help for available commands."
	}

	if !strings.HasPrefix(input, "/") {
		return ""
	}

	input = strings.TrimPrefix(input, "/")
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return "No command provided."
	}

	cmdName := parts[0]
	var args []string
	if len(parts) > 1 {
		args = parts[1:]
	}

	r.mu.RLock()
	cmd, ok := r.commands[cmdName]
	if !ok {
		if resolved, exists := r.aliases[cmdName]; exists {
			cmd = r.commands[resolved]
		}
	}
	r.mu.RUnlock()

	if cmd == nil {
		return fmt.Sprintf("Unknown command: /%s. Type /help for available commands.", cmdName)
	}

	return cmd.Handler(args)
}

func (r *Registry) ListCommands() map[CommandCategory][]*Command {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[CommandCategory][]*Command)
	for _, cmd := range r.commands {
		result[cmd.Category] = append(result[cmd.Category], cmd)
	}
	return result
}

func (r *Registry) ListAll() []*Command {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*Command, 0, len(r.commands))
	for _, cmd := range r.commands {
		result = append(result, cmd)
	}
	return result
}

func (r *Registry) HandleSlash(input string) string {
	input = strings.TrimSpace(input)
	if input == "" || !strings.HasPrefix(input, "/") {
		return ""
	}
	return r.Dispatch(input)
}

func (r *Registry) Get(name string) *Command {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if cmd, ok := r.commands[name]; ok {
		return cmd
	}
	if resolved, ok := r.aliases[name]; ok {
		return r.commands[resolved]
	}
	return nil
}
