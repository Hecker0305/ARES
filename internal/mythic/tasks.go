package mythic

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type TaskChain struct {
	ID         string      `json:"id"`
	CallbackID int         `json:"callback_id"`
	Tasks      []MythicTask `json:"tasks"`
	Status     string      `json:"status"`
	Current    int         `json:"current"`
	CreatedAt  time.Time   `json:"created_at"`
}

type ScheduledTask struct {
	ID         string `json:"id"`
	CallbackID int    `json:"callback_id"`
	CronExpr   string `json:"cron_expr"`
	Command    string `json:"command"`
	Active     bool   `json:"active"`
}

var taskChains = make(map[string]*TaskChain)
var scheduledTasks = make(map[string]*ScheduledTask)

func (e *MythicEngine) CreateTaskChain(callbackID int, commands []string) ([]MythicTask, error) {
	var tasks []MythicTask
	for _, cmd := range commands {
		params := map[string]interface{}{
			"command": cmd,
			"chain":   true,
		}
		task, err := e.SubmitTask(callbackID, cmd, params)
		if err != nil {
			return tasks, fmt.Errorf("create task chain at '%s': %w", cmd, err)
		}
		tasks = append(tasks, *task)
	}

	chain := &TaskChain{
		ID:         uuid.New(),
		CallbackID: callbackID,
		Tasks:      tasks,
		Status:     "created",
		Current:    0,
		CreatedAt:  time.Now(),
	}
	taskChains[chain.ID] = chain

	result := fmt.Sprintf("[+] Task chain %s created with %d commands for callback %d", chain.ID, len(commands), callbackID)
	logger.Info("[Mythic] " + result)
	return tasks, nil
}

func (e *MythicEngine) ExecuteTaskChain(chainID string) (string, error) {
	chain, ok := taskChains[chainID]
	if !ok {
		return "", fmt.Errorf("task chain %s not found", chainID)
	}

	chain.Status = "running"
	go func() {
		for i, task := range chain.Tasks {
			chain.Current = i
			chain.Tasks[i].Status = "submitted"

			for j := 0; j < 60; j++ {
				result, err := e.GetTaskResult(task.ID)
				if err != nil {
					chain.Tasks[i].Status = "error"
					chain.Status = "failed"
					return
				}
				if result.Status == "completed" || result.Status == "error" {
					chain.Tasks[i].Status = result.Status
					chain.Tasks[i].Result = result.Result
					break
				}
				time.Sleep(2 * time.Second)
			}

			if chain.Tasks[i].Status != "completed" {
				chain.Status = "failed"
				return
			}
		}
		chain.Status = "completed"
	}()

	return fmt.Sprintf("[+] Task chain %s execution started (%d tasks)", chainID, len(chain.Tasks)), nil
}

func (e *MythicEngine) GetTaskChainStatus(chainID string) (string, error) {
	chain, ok := taskChains[chainID]
	if !ok {
		return "", fmt.Errorf("task chain %s not found", chainID)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Task Chain: %s [%s]\n", chainID, chain.Status))
	b.WriteString(fmt.Sprintf("Callback: %d\n", chain.CallbackID))
	b.WriteString(fmt.Sprintf("Tasks: %d/%d completed\n", chain.Current, len(chain.Tasks)))
	b.WriteString("\n")

	for i, task := range chain.Tasks {
		status := "pending"
		if task.Status != "" {
			status = task.Status
		}
		b.WriteString(fmt.Sprintf("  [%d/%d] Task %d: %s [%s]\n", i+1, len(chain.Tasks), task.ID, task.Command, status))
	}

	return b.String(), nil
}

func (e *MythicEngine) CreateScheduledTask(callbackID int, cronExpr, command string) (string, error) {
	st := &ScheduledTask{
		ID:         uuid.New(),
		CallbackID: callbackID,
		CronExpr:   cronExpr,
		Command:    command,
		Active:     true,
	}
	scheduledTasks[st.ID] = st

	result := fmt.Sprintf("[+] Scheduled task %s: callback %d, cron '%s', command '%s'",
		st.ID, callbackID, cronExpr, command)
	logger.Info("[Mythic] " + result)
	return result, nil
}

func (e *MythicEngine) TaskChainFromFile(chainDefPath string) (string, error) {
	data, err := os.ReadFile(chainDefPath)
	if err != nil {
		return "", fmt.Errorf("read chain file: %w", err)
	}

	var chainDef struct {
		CallbackID int      `json:"callback_id"`
		Commands   []string `json:"commands"`
	}
	if err := json.Unmarshal(data, &chainDef); err != nil {
		return "", fmt.Errorf("parse chain file: %w", err)
	}

	tasks, err := e.CreateTaskChain(chainDef.CallbackID, chainDef.Commands)
	if err != nil {
		return "", fmt.Errorf("create chain from file: %w", err)
	}

	return fmt.Sprintf("[+] Task chain loaded from %s with %d commands, created %d tasks",
		chainDefPath, len(chainDef.Commands), len(tasks)), nil
}

func (e *MythicEngine) ListTaskChains() []TaskChain {
	var result []TaskChain
	for _, chain := range taskChains {
		result = append(result, *chain)
	}
	return result
}

func (e *MythicEngine) AbortTaskChain(chainID string) (string, error) {
	chain, ok := taskChains[chainID]
	if !ok {
		return "", fmt.Errorf("task chain %s not found", chainID)
	}
	chain.Status = "aborted"
	return fmt.Sprintf("[+] Task chain %s aborted", chainID), nil
}

func (e *MythicEngine) RemoveScheduledTask(taskID string) (string, error) {
	if _, ok := scheduledTasks[taskID]; !ok {
		return "", fmt.Errorf("scheduled task %s not found", taskID)
	}
	delete(scheduledTasks, taskID)
	return fmt.Sprintf("[+] Scheduled task %s removed", taskID), nil
}

func (e *MythicEngine) ListScheduledTasks(callbackID int) []ScheduledTask {
	var result []ScheduledTask
	for _, st := range scheduledTasks {
		if callbackID == 0 || st.CallbackID == callbackID {
			result = append(result, *st)
		}
	}
	return result
}
