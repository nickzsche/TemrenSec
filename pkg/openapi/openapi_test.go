package openapi

import "testing"

const sampleV3 = `{
  "openapi": "3.0.0",
  "info": {"title": "Pet Store", "version": "1.0"},
  "servers": [{"url": "https://api.example.com/v1"}],
  "paths": {
    "/pets": {
      "get": {"tags": ["pets"], "parameters": [{"name": "limit", "in": "query"}]},
      "post": {"tags": ["pets"]}
    },
    "/pets/{id}": {
      "get": {"parameters": [{"name": "id", "in": "path"}]}
    }
  }
}`

const sampleV2 = `{
  "swagger": "2.0",
  "info": {"title": "Legacy", "version": "1.0"},
  "host": "legacy.example.com",
  "basePath": "/api",
  "schemes": ["https"],
  "paths": {
    "/users": {"get": {}, "post": {}},
    "/users/{id}": {"delete": {"parameters": [{"name": "id", "in": "path", "type": "string"}]}}
  }
}`

func TestParseV3(t *testing.T) {
	spec, err := Parse([]byte(sampleV3), "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Title != "Pet Store" {
		t.Errorf("title=%q", spec.Title)
	}
	if len(spec.Operations) != 3 {
		t.Errorf("ops=%d", len(spec.Operations))
	}
	for _, op := range spec.Operations {
		if op.URL == "" || op.URL[0] != 'h' {
			t.Errorf("missing baseURL on op %s %s — got %q", op.Method, op.Path, op.URL)
		}
	}
}

func TestParseV2(t *testing.T) {
	spec, err := Parse([]byte(sampleV2), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Operations) != 3 {
		t.Errorf("ops=%d", len(spec.Operations))
	}
	for _, op := range spec.Operations {
		if op.URL == "" || op.URL[:5] != "https" {
			t.Errorf("URL not constructed: %q", op.URL)
		}
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	_, err := Parse([]byte("not yaml or json"), "")
	if err == nil {
		t.Errorf("expected error")
	}
}
