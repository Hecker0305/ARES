package skills

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ares/engine/internal/logger"
	"gopkg.in/yaml.v3"
)

// FrameworkMappings holds cross-framework references for a skill.
type FrameworkMappings struct {
	MITREAttack []string `yaml:"mitre_attack" json:"mitre_attack"`
	NISTCSF     []string `yaml:"nist_csf" json:"nist_csf"`
	MITREAtlas  []string `yaml:"mitre_atlas" json:"mitre_atlas"`
	D3Fend      []string `yaml:"d3fend" json:"d3fend"`
	NISTAIRMF   []string `yaml:"nist_ai_rmf" json:"nist_ai_rmf"`
}

// SkillFrontmatter is the YAML frontmatter (~30 tokens) for progressive disclosure.
type SkillFrontmatter struct {
	Name              string   `yaml:"name" json:"name"`
	Description       string   `yaml:"description" json:"description"`
	Domain            string   `yaml:"domain" json:"domain"`
	Subdomain         string   `yaml:"subdomain" json:"subdomain"`
	Tags              []string `yaml:"tags" json:"tags"`
	Version           string   `yaml:"version" json:"version"`
	Author            string   `yaml:"author" json:"author"`
	License           string   `yaml:"license" json:"license"`
	FrameworkMappings `yaml:",inline" json:",inline"`
}

// Skill represents a complete agentskills.io standard skill.
type Skill struct {
	ID               string `json:"id"`
	SkillFrontmatter `yaml:",inline" json:",inline"`
	WhenToUse        string `json:"when_to_use"`
	Prerequisites    string `json:"prerequisites"`
	Workflow         string `json:"workflow"`
	Verification     string `json:"verification"`
	ReferencesPath   string `json:"references_path,omitempty"`
	ScriptsPath      string `json:"scripts_path,omitempty"`
	AssetsPath       string `json:"assets_path,omitempty"`
	Content          string `json:"content"`
}

// Loader manages discovery and loading of skills.
type Loader struct {
	skills   map[string]*Skill
	rootPath string
}

func NewLoader() *Loader {
	return &Loader{skills: make(map[string]*Skill)}
}

// parseYAMLFrontmatter extracts YAML frontmatter delimited by --- from raw content.
func parseYAMLFrontmatter(data []byte) (SkillFrontmatter, string, error) {
	content := string(data)
	var fm SkillFrontmatter

	if !strings.HasPrefix(content, "---\n") {
		return fm, content, fmt.Errorf("missing YAML frontmatter delimiter")
	}

	endIdx := strings.Index(content[4:], "\n---\n")
	if endIdx == -1 {
		return fm, content, fmt.Errorf("missing closing YAML frontmatter delimiter")
	}
	endIdx += 4

	frontmatterStr := content[4:endIdx]
	body := content[endIdx+5:]

	if err := yaml.Unmarshal([]byte(frontmatterStr), &fm); err != nil {
		return fm, content, fmt.Errorf("failed to parse YAML frontmatter: %w", err)
	}
	return fm, body, nil
}

// Load discovers skills from the skills_v2/ directory tree.
func Load() (*Loader, error) {
	loader := NewLoader()

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get cwd: %w", err)
	}

	root := findGoModRoot(cwd)
	locations := []string{
		filepath.Join(root, "skills_v2"),
		filepath.Join(root, "ares", "skills_v2"),
		filepath.Join(root, "internal", "skills_v2"),
	}

	var loadedFrom string
	for _, loc := range locations {
		if info, err := os.Stat(loc); err == nil && info.IsDir() {
			if err := loadSkillsFromDir(loader, loc); err == nil && loader.Count() > 0 {
				loadedFrom = loc
				loader.rootPath = loc
				break
			}
		}
	}

	if loadedFrom == "" {
		logger.Warn("[Skills] No skills_v2 directory found. Creating default skills.")
		createDefaultSkills(loader)
	}

	return loader, nil
}

func findGoModRoot(dir string) string {
	for dir != "" && dir != "." {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return dir
}

func loadSkillsFromDir(loader *Loader, baseDir string) error {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("failed to resolve base directory: %w", err)
	}

	return filepath.Walk(absBase, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if filepath.Base(path) != "SKILL.md" {
			return nil
		}

		absPath, err := filepath.Abs(path)
		if err != nil {
			logger.Error(fmt.Sprintf("[Skills] Failed to resolve path %s: %v", path, err))
			return nil
		}
		if !strings.HasPrefix(absPath, absBase) {
			logger.Error(fmt.Sprintf("[Skills] Path traversal blocked: %s", absPath))
			return nil
		}
		if info.Size() > 1<<20 {
			logger.Error(fmt.Sprintf("[Skills] File too large: %s (%d bytes)", path, info.Size()))
			return nil
		}

		loadSkillFromFile(loader, path)
		return nil
	})
}

func loadSkillFromFile(loader *Loader, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Error(fmt.Sprintf("[Skills] Failed to read %s: %v", path, err))
		return
	}

	if len(data) > 1<<20 {
		logger.Error(fmt.Sprintf("[Skills] File too large: %s", path))
		return
	}

	fm, body, err := parseYAMLFrontmatter(data)
	if err != nil {
		logger.Error(fmt.Sprintf("[Skills] Failed to parse frontmatter in %s: %v", path, err))
		return
	}

	skillDir := filepath.Dir(path)
	skill := &Skill{
		ID:               fm.Name,
		SkillFrontmatter: fm,
		ReferencesPath:   findDir(skillDir, "references"),
		ScriptsPath:      findDir(skillDir, "scripts"),
		AssetsPath:       findDir(skillDir, "assets"),
	}

	sections := parseSkillBody(body)
	skill.WhenToUse = sections["when to use"]
	skill.Prerequisites = sections["prerequisites"]
	skill.Workflow = sections["workflow"]
	skill.Verification = sections["verification"]
	skill.Content = body

	if skill.ID == "" {
		skill.ID = strings.TrimSuffix(filepath.Base(path), ".md")
	}

	loader.skills[skill.ID] = skill
}

func findDir(base, name string) string {
	d := filepath.Join(base, name)
	if info, err := os.Stat(d); err == nil && info.IsDir() {
		return d
	}
	return ""
}

// parseSkillBody extracts sections from the markdown body using ## headings.
func parseSkillBody(body string) map[string]string {
	sections := make(map[string]string)
	lines := strings.Split(body, "\n")
	var currentSection string
	var currentContent []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "## ") {
			if currentSection != "" {
				sections[strings.ToLower(currentSection)] = strings.TrimSpace(strings.Join(currentContent, "\n"))
			}
			currentSection = strings.TrimPrefix(trimmed, "## ")
			currentContent = nil
		} else {
			currentContent = append(currentContent, line)
		}
	}
	if currentSection != "" {
		sections[strings.ToLower(currentSection)] = strings.TrimSpace(strings.Join(currentContent, "\n"))
	}
	return sections
}

// DiscoverySkill returns only the frontmatter fields for lightweight discovery.
func (s *Skill) DiscoverySkill() SkillFrontmatter {
	return s.SkillFrontmatter
}

// LoadFullSkill returns the complete skill including workflow, prerequisites, and verification.
func (s *Skill) LoadFullSkill() *Skill {
	return s
}

func (l *Loader) All() []Skill {
	var result []Skill
	for _, s := range l.skills {
		result = append(result, *s)
	}
	return result
}

func (l *Loader) Get(name string) *Skill {
	s, ok := l.skills[name]
	if !ok {
		return nil
	}
	return s
}

func (l *Loader) Add(skill Skill) {
	l.skills[skill.ID] = &skill
}

func (l *Loader) GetSkill(skillName string) string {
	s := l.Get(skillName)
	if s == nil {
		return fmt.Sprintf("Skill '%s' not found", skillName)
	}
	return s.Content
}

func (l *Loader) GetSkillMetadata(skillName string) (map[string]string, error) {
	s := l.Get(skillName)
	if s == nil {
		return nil, fmt.Errorf("skill '%s' not found", skillName)
	}
	return map[string]string{
		"name":        s.Name,
		"description": s.Description,
		"domain":      s.Domain,
		"subdomain":   s.Subdomain,
		"version":     s.Version,
		"author":      s.Author,
		"license":     s.License,
		"tags":        strings.Join(s.Tags, ","),
	}, nil
}

func (l *Loader) ListSkills() []string {
	var names []string
	for name := range l.skills {
		names = append(names, name)
	}
	return names
}

func (l *Loader) ListDiscovered() []SkillFrontmatter {
	var result []SkillFrontmatter
	for _, s := range l.skills {
		result = append(result, s.DiscoverySkill())
	}
	return result
}

func (l *Loader) Count() int {
	return len(l.skills)
}

func (l *Loader) SkillsByPhase() map[string][]Skill {
	phases := make(map[string][]Skill)
	for _, s := range l.skills {
		phase := s.Domain
		phases[phase] = append(phases[phase], *s)
	}
	return phases
}

func createDefaultSkills(loader *Loader) {
	defaultSkills := []Skill{
		{
			ID: "web-recon",
			SkillFrontmatter: SkillFrontmatter{
				Name:        "web-recon",
				Description: "Comprehensive web application reconnaissance using passive and active techniques to enumerate attack surface.",
				Domain:      "web-security",
				Subdomain:   "reconnaissance",
				Tags:        []string{"recon", "web", "enumeration"},
				Version:     "1.0",
				Author:      "ARES Team",
				License:     "Apache-2.0",
			},
			WhenToUse:     "During initial engagement phase to map target web application surface.",
			Prerequisites: "Network access to target, optional authentication credentials.",
			Workflow:      "1. Passive recon via search engines\n2. Active scanning with directory enumeration\n3. Technology fingerprinting\n4. Endpoint discovery",
			Verification:  "Verify discovered endpoints respond correctly and are documented.",
			Content:       "# Web Recon\n\n## When to Use\n...\n## Prerequisites\n...\n## Workflow\n...\n## Verification\n...",
		},
	}

	for _, skill := range defaultSkills {
		loader.Add(skill)
	}
}
