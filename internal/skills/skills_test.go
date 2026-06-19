package skills

import (
	"fmt"
	"testing"
)

func TestSkillsLoading(t *testing.T) {
	// Test loading skills
	loader, err := Load()
	if err != nil {
		t.Fatalf("Failed to load skills: %v", err)
	}

	// Test that skills were loaded
	if loader.Count() == 0 {
		t.Error("No skills were loaded")
	}

	// Test listing skills
	skills := loader.ListSkills()
	if len(skills) == 0 {
		t.Error("No skills in list")
	}

	// Test getting specific skills
	for _, skillName := range skills {
		content := loader.GetSkill(skillName)
		if content == "" {
			t.Errorf("Skill %s has empty content", skillName)
		}

		// Test getting metadata
		metadata, err := loader.GetSkillMetadata(skillName)
		if err != nil {
			t.Errorf("Failed to get metadata for skill %s: %v", skillName, err)
		}

		if metadata["author"] == "" {
			t.Errorf("Skill %s missing author metadata", skillName)
		}
	}

	// Test skills by phase
	byPhase := loader.SkillsByPhase()
	if len(byPhase) == 0 {
		t.Error("No phases found")
	}

	fmt.Printf("Loaded %d skills across %d phases\n", loader.Count(), len(byPhase))
	for phase, phaseSkills := range byPhase {
		fmt.Printf("  Phase %s: %d skills\n", phase, len(phaseSkills))
	}
}

func TestSkillNotFound(t *testing.T) {
	loader, _ := Load()
	content := loader.GetSkill("nonexistent_skill")
	expected := "Skill 'nonexistent_skill' not found"
	if content != expected {
		t.Errorf("Expected '%s', got '%s'", expected, content)
	}
}
