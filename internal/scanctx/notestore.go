package scanctx

import (
	"strings"
	"sync"
	"time"
)

type Note struct {
	ID        int
	Content   string
	Tags      []string
	CreatedAt time.Time
	Phase     string
}

type NoteStore struct {
	mu    sync.RWMutex
	notes []Note
}

func NewNoteStore() *NoteStore {
	return &NoteStore{}
}

func (ns *NoteStore) Add(content string, tags []string, phase string) int {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	note := Note{
		ID:        len(ns.notes),
		Content:   content,
		Tags:      tags,
		CreatedAt: time.Now(),
		Phase:     phase,
	}
	ns.notes = append(ns.notes, note)
	return note.ID
}

func (ns *NoteStore) Search(query string) []Note {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	query = strings.ToLower(query)
	result := make([]Note, 0)
	for i := range ns.notes {
		if strings.Contains(strings.ToLower(ns.notes[i].Content), query) {
			cp := ns.notes[i]
			cp.Tags = make([]string, len(ns.notes[i].Tags))
			copy(cp.Tags, ns.notes[i].Tags)
			result = append(result, cp)
		}
	}
	return result
}

func (ns *NoteStore) ByTag(tag string) []Note {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	result := make([]Note, 0)
	for i := range ns.notes {
		for _, t := range ns.notes[i].Tags {
			if t == tag {
				cp := ns.notes[i]
				cp.Tags = make([]string, len(ns.notes[i].Tags))
				copy(cp.Tags, ns.notes[i].Tags)
				result = append(result, cp)
				break
			}
		}
	}
	return result
}

func (ns *NoteStore) ByPhase(phase string) []Note {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	result := make([]Note, 0)
	for i := range ns.notes {
		if ns.notes[i].Phase == phase {
			cp := ns.notes[i]
			cp.Tags = make([]string, len(ns.notes[i].Tags))
			copy(cp.Tags, ns.notes[i].Tags)
			result = append(result, cp)
		}
	}
	return result
}

func (ns *NoteStore) All() []Note {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	result := make([]Note, len(ns.notes))
	for i := range ns.notes {
		cp := ns.notes[i]
		cp.Tags = make([]string, len(ns.notes[i].Tags))
		copy(cp.Tags, ns.notes[i].Tags)
		result[i] = cp
	}
	return result
}

func (ns *NoteStore) Remove(id int) bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	for i, n := range ns.notes {
		if n.ID == id {
			ns.notes = append(ns.notes[:i], ns.notes[i+1:]...)
			return true
		}
	}
	return false
}
