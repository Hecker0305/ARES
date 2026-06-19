package simulate

import "testing"

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestRunCampaign(t *testing.T) {
	e := New()
	campaign := e.RunCampaign("target.com", "APT29")
	if campaign == nil {
		t.Fatal("expected campaign")
	}
	if campaign.Target != "target.com" {
		t.Errorf("expected target.com, got %s", campaign.Target)
	}
}

func TestRunCampaignUnknownActor(t *testing.T) {
	e := New()
	campaign := e.RunCampaign("target.com", "unknown")
	if campaign == nil {
		t.Fatal("expected campaign even for unknown actor")
	}
}

func TestCampaignNarrative(t *testing.T) {
	e := New()
	campaign := e.RunCampaign("test.com", "FIN7")
	narrative := campaign.Narrative()
	if narrative == "" {
		t.Error("expected non-empty narrative")
	}
}

func TestRansomwareChain(t *testing.T) {
	e := New()
	chain := e.RansomwareChain("target.com")
	if len(chain) == 0 {
		t.Error("expected non-empty chain")
	}
}

func TestInsiderThreatPath(t *testing.T) {
	e := New()
	path := e.InsiderThreatPath("target.com")
	if len(path) == 0 {
		t.Error("expected non-empty path")
	}
}

func TestCloudCompromisePath(t *testing.T) {
	e := New()
	path := e.CloudCompromisePath("target.com")
	if len(path) == 0 {
		t.Error("expected non-empty path")
	}
}

func TestCampaigns(t *testing.T) {
	e := New()
	e.RunCampaign("a.com", "APT29")
	e.RunCampaign("b.com", "FIN7")
	campaigns := e.Campaigns()
	if len(campaigns) != 2 {
		t.Errorf("expected 2 campaigns, got %d", len(campaigns))
	}
}

func TestActors(t *testing.T) {
	e := New()
	actors := e.Actors()
	if len(actors) == 0 {
		t.Error("expected seeded actors")
	}
}

func TestStageConstants(t *testing.T) {
	if StageRecon != "recon" {
		t.Error("StageRecon mismatch")
	}
	if StageExploit != "exploit" {
		t.Error("StageExploit mismatch")
	}
	if StageC2 != "command_and_control" {
		t.Error("StageC2 mismatch")
	}
}
