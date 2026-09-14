package wafbypass

import (
	"net/http/httptest"
	"testing"
)

func TestNewBypasser(t *testing.T) {
	tests := []struct {
		name    string
		wafType WAFType
	}{
		{"Cloudflare", WAFCloudflare},
		{"Akamai", WAFAkamai},
		{"Imperva", WAFImperva},
		{"AWS", WAFAWS},
		{"Generic", WAFGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBypasser(tt.wafType)
			if b == nil {
				t.Fatal("Expected bypasser to be created")
			}
			if b.wafType != tt.wafType {
				t.Errorf("Expected wafType %s, got %s", tt.wafType, b.wafType)
			}
			if len(b.strategies) == 0 && tt.wafType != WAFGeneric {
				t.Error("Expected strategies to be loaded")
			}
		})
	}
}

func TestWAFDetector(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		expected   WAFType
	}{
		{
			name: "Cloudflare detection",
			headers: map[string]string{
				"CF-RAY": "1234567890",
			},
			expected: WAFCloudflare,
		},
		{
			name: "Akamai detection",
			headers: map[string]string{
				"X-Akamai-Request-BC": "test",
			},
			expected: WAFAkamai,
		},
		{
			name: "Imperva detection",
			headers: map[string]string{
				"X-WAF": "imperva",
			},
			expected: WAFImperva,
		},
		{
			name:     "Generic detection",
			headers:  map[string]string{},
			expected: WAFGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			for k, v := range tt.headers {
				recorder.Header().Set(k, v)
			}
			resp := recorder.Result()
			
			wafType := WAFDetector(resp)
			if wafType != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, wafType)
			}
		})
	}
}

func TestApplyRandom(t *testing.T) {
	b := NewBypasser(WAFCloudflare)
	req := httptest.NewRequest("GET", "http://example.com", nil)

	err := b.ApplyAll(req)
	if err != nil {
		t.Errorf("ApplyAll failed: %v", err)
	}

	if req.Header.Get("User-Agent") == "" {
		t.Error("Expected User-Agent to be set")
	}
}

func TestGetRandomUserAgent(t *testing.T) {
	ua1 := GetRandomUserAgent()
	ua2 := GetRandomUserAgent()
	
	if ua1 == "" {
		t.Error("Expected non-empty user agent")
	}
	
	found := false
	for _, ua := range UserAgents {
		if ua == ua1 {
			found = true
			break
		}
	}
	if !found {
		t.Error("User agent not in list")
	}
	
	if ua1 == ua2 {
		t.Log("Note: Same user agent selected (random chance)")
	}
}

func TestApplyPathEncoding(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://example.com/admin", "http://example.com%2fadmin"},
		{"http://example.com/api/users", "http://example.com%2fapi%2fusers"},
	}

	for _, tt := range tests {
		result, err := ApplyPathEncoding(tt.input)
		if err != nil {
			t.Errorf("ApplyPathEncoding failed: %v", err)
		}
		if result != tt.expected {
			t.Errorf("Expected %s, got %s", tt.expected, result)
		}
	}
}

func TestApplyCaseTampering(t *testing.T) {
	input := "http://example.com/admin"
	result, err := ApplyCaseTampering(input)
	if err != nil {
		t.Errorf("ApplyCaseTampering failed: %v", err)
	}
	if result == input {
		t.Error("Expected case-tampered result")
	}
}

func TestApplyCommentInjection(t *testing.T) {
	input := "http://example.com/admin"
	result, err := ApplyCommentInjection(input)
	if err != nil {
		t.Errorf("ApplyCommentInjection failed: %v", err)
	}
	if result == input {
		t.Error("Expected comment-injected result")
	}
}

func TestGetAllURLMutations(t *testing.T) {
	mutations := GetAllURLMutations()
	if len(mutations) == 0 {
		t.Error("Expected mutations to be returned")
	}
	
	expected := []string{"Path Encoding", "Case Tampering", "Comment Injection", "Path Traversal", "Double Encoding", "Null Byte"}
	if len(mutations) != len(expected) {
		t.Errorf("Expected %d mutations, got %d", len(expected), len(mutations))
	}
}

func TestGenerateAllMutations(t *testing.T) {
	input := "http://example.com/admin"
	results, err := GenerateAllMutations(input)
	if err != nil {
		t.Errorf("GenerateAllMutations failed: %v", err)
	}
	if len(results) == 0 {
		t.Error("Expected mutations to be generated")
	}
	
	for _, r := range results {
		if r == "" {
			t.Error("Expected non-empty mutation")
		}
	}
}
