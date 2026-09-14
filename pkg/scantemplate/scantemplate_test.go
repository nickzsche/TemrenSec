package scantemplate

import (
	"testing"
)

func TestLoadHappyPath(t *testing.T) {
	yamlBlob := []byte(`name: nightly-prod
profile: deep
targets:
  - https://api.example.com
  - https://www.example.com
skip:
  - storybook_exposure
headers:
  X-Temren-Run: nightly
auth:
  type: bearer
  token: tok_xxx
notify:
  - pagerduty
  - slack
policy: examples/policy.yaml
tags: [prod, pci]
schedule: "0 4 * * *"
`)
	tpl, err := Load(yamlBlob)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpl.Validate(); err != nil {
		t.Fatal(err)
	}
	if tpl.Profile != "deep" || len(tpl.Targets) != 2 || tpl.Auth.Type != "bearer" {
		t.Errorf("bad parse: %+v", tpl)
	}
}

func TestLoadRequiresTargets(t *testing.T) {
	_, err := Load([]byte(`name: bad`))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateAuthBranches(t *testing.T) {
	bad := &Template{Name: "x", Targets: []string{"http://x"}, Auth: &Auth{Type: "basic"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected basic without creds to fail")
	}
	bad2 := &Template{Name: "x", Targets: []string{"http://x"}, Auth: &Auth{Type: "weird"}}
	if err := bad2.Validate(); err == nil {
		t.Fatal("expected unknown auth type to fail")
	}
}
