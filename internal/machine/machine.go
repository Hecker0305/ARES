package machine

import (
	"fmt"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

type State string

const (
	StateDiscovered    State = "discovered"
	StateFingerprinted State = "fingerprinted"
	StateTesting       State = "testing"
	StateVerified      State = "verified"
	StateFalsePositive State = "false_positive"
	StateChained       State = "chained"
	StateEscalated     State = "escalated"
	StateReported      State = "reported"
	StatePatched       State = "patched"
	StateClosed        State = "closed"
)

type Transition struct {
	From         State     `json:"from"`
	To           State     `json:"to"`
	Event        string    `json:"event"`
	Time         time.Time `json:"time"`
	Forced       bool      `json:"forced"`
	AuthorizedBy string    `json:"authorized_by,omitempty"`
}

type StateMachine struct {
	mu          sync.RWMutex
	current     State
	transitions []Transition
	allowed     map[State][]State
	callbacks   map[State][]func()
	id          string
	locked      bool
	forceReason string
}

func New(id string, initial State) *StateMachine {
	sm := &StateMachine{
		current:     initial,
		transitions: make([]Transition, 0),
		allowed:     make(map[State][]State),
		callbacks:   make(map[State][]func()),
		id:          id,
	}
	sm.setDefaults()
	return sm
}

func (sm *StateMachine) setDefaults() {
	sm.allowed[StateDiscovered] = []State{StateFingerprinted, StateTesting, StateFalsePositive}
	sm.allowed[StateFingerprinted] = []State{StateTesting, StateFalsePositive}
	sm.allowed[StateTesting] = []State{StateVerified, StateFalsePositive, StateDiscovered}
	sm.allowed[StateVerified] = []State{StateChained, StateFalsePositive}
	sm.allowed[StateChained] = []State{StateEscalated, StateVerified}
	sm.allowed[StateEscalated] = []State{StateReported, StateChained}
	sm.allowed[StateReported] = []State{StatePatched, StateClosed}
	sm.allowed[StatePatched] = []State{StateClosed}
}

func (sm *StateMachine) LockTransitions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.locked = true
}

func (sm *StateMachine) Transition(to State) error {
	sm.mu.Lock()

	if sm.locked {
		sm.mu.Unlock()
		return fmt.Errorf("state machine is locked; transitions are disabled")
	}

	allowed, ok := sm.allowed[sm.current]
	if !ok {
		sm.mu.Unlock()
		return fmt.Errorf("state %s has no allowed transitions", sm.current)
	}
	valid := false
	for _, s := range allowed {
		if s == to {
			valid = true
			break
		}
	}
	if !valid {
		sm.mu.Unlock()
		return fmt.Errorf("cannot transition from %s to %s", sm.current, to)
	}

	sm.transitions = append(sm.transitions, Transition{
		From:  sm.current,
		To:    to,
		Event: fmt.Sprintf("%s->%s", sm.current, to),
		Time:  time.Now(),
	})
	sm.current = to

	callbacks := make([]func(), len(sm.callbacks[to]))
	copy(callbacks, sm.callbacks[to])
	sm.mu.Unlock()

	for _, cb := range callbacks {
		cb()
	}

	return nil
}

func (sm *StateMachine) Force(to State, reason, authorizedBy string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.current == StateClosed || sm.current == StatePatched {
		return fmt.Errorf("cannot force transition from terminal state %s", sm.current)
	}

	from := sm.current
	sm.current = to
	sm.transitions = append(sm.transitions, Transition{
		From:         from,
		To:           to,
		Event:        "force",
		Time:         time.Now(),
		Forced:       true,
		AuthorizedBy: authorizedBy,
	})

	sm.forceReason = reason
	logger.Warn(fmt.Sprintf("[StateMachine] FORCE transition %s -> %s: %s (authorized by: %s)", from, to, reason, authorizedBy))

	return nil
}

func (sm *StateMachine) Current() State {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.current
}

func (sm *StateMachine) OnEnter(state State, fn func()) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.callbacks[state] = append(sm.callbacks[state], fn)
}

func (sm *StateMachine) CanTransition(to State) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	allowed, ok := sm.allowed[sm.current]
	if !ok {
		return false
	}
	for _, s := range allowed {
		if s == to {
			return true
		}
	}
	return false
}

func (sm *StateMachine) History() []Transition {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]Transition, len(sm.transitions))
	copy(result, sm.transitions)
	return result
}

func (sm *StateMachine) IsTerminal() bool {
	return sm.current == StateClosed
}

func (sm *StateMachine) AddTransition(from, to State) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.locked {
		return fmt.Errorf("state machine is locked; cannot add transitions")
	}

	for _, existing := range sm.allowed[from] {
		if existing == to {
			return nil
		}
	}

	sm.allowed[from] = append(sm.allowed[from], to)
	return nil
}

func (sm *StateMachine) ID() string { return sm.id }

func (sm *StateMachine) String() string {
	return fmt.Sprintf("StateMachine[%s]: %s (%d transitions)", sm.id, sm.current, len(sm.transitions))
}

func (sm *StateMachine) ForceReason() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.forceReason
}

func (sm *StateMachine) IsLocked() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.locked
}
