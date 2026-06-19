package graphql

import (
	"context"
	"testing"
)

func TestNewPipeline(t *testing.T) {
	p := NewPipeline("http://localhost:8080/graphql", nil)
	if p == nil {
		t.Fatal("expected non-nil pipeline")
	}
}

func TestGetMutations(t *testing.T) {
	p := NewPipeline("http://localhost:8080/graphql", nil)
	mutations := p.GetMutations()
	_ = mutations
}

func TestGetQueries(t *testing.T) {
	p := NewPipeline("http://localhost:8080/graphql", nil)
	queries := p.GetQueries()
	_ = queries
}

func TestRunPipeline(t *testing.T) {
	results := RunPipeline(context.Background(), "http://localhost:8080/graphql", nil, "", "", "")
	_ = results
}

func TestIntrospect(t *testing.T) {
	p := NewPipeline("http://localhost:9999/graphql", nil)
	schema, _ := p.Introspect(context.Background())
	_ = schema
}
