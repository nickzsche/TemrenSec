package auth

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func TestNewSAMLServiceProvider(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml/metadata",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)
	if sp.config.IDPMetadataURL != config.IDPMetadataURL {
		t.Errorf("expected IDPMetadataURL %s, got %s", config.IDPMetadataURL, sp.config.IDPMetadataURL)
	}
	if sp.config.SPEntityID != config.SPEntityID {
		t.Errorf("expected SPEntityID %s, got %s", config.SPEntityID, sp.config.SPEntityID)
	}
}

func TestGenerateAuthRequest(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)
	encoded, err := sp.GenerateAuthRequest()
	if err != nil {
		t.Fatalf("GenerateAuthRequest() error: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode error: %v", err)
	}

	xmlStr := string(decoded)
	if !strings.Contains(xmlStr, "samlp:AuthnRequest") {
		t.Error("auth request should contain samlp:AuthnRequest element")
	}
	if !strings.Contains(xmlStr, sp.config.SPEntityID) {
		t.Error("auth request should contain SP entity ID")
	}
	if !strings.Contains(xmlStr, sp.config.AcsURL) {
		t.Error("auth request should contain ACS URL")
	}
	if !strings.Contains(xmlStr, `Version="2.0"`) {
		t.Error("auth request should specify SAML 2.0 version")
	}
	if !strings.Contains(xmlStr, `xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`) {
		t.Error("auth request should contain SAML protocol namespace")
	}
}

func TestParseResponse(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)

	samlResponseXML := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response123" IssueInstant="%s">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion123" IssueInstant="%s">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s"/>
    <saml:AuthnStatement AuthnInstant="%s" SessionIndex="_session123"/>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>user@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="groups">
        <saml:AttributeValue>admin</saml:AttributeValue>
        <saml:AttributeValue>developers</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`,
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		time.Now().Add(-1*time.Hour).UTC().Format("2006-01-02T15:04:05Z"),
		time.Now().Add(1*time.Hour).UTC().Format("2006-01-02T15:04:05Z"),
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	)

	encoded := base64.StdEncoding.EncodeToString([]byte(samlResponseXML))
	assertion, err := sp.ParseResponse(encoded)
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}

	if assertion.NameID != "user@example.com" {
		t.Errorf("expected NameID 'user@example.com', got %s", assertion.NameID)
	}
	if assertion.Email != "user@example.com" {
		t.Errorf("expected Email 'user@example.com', got %s", assertion.Email)
	}
	if assertion.Issuer != "https://idp.example.com" {
		t.Errorf("expected Issuer 'https://idp.example.com', got %s", assertion.Issuer)
	}
	if len(assertion.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(assertion.Groups))
	}
	if assertion.SessionIndex != "_session123" {
		t.Errorf("expected SessionIndex '_session123', got %s", assertion.SessionIndex)
	}
}

func TestParseResponseInvalidBase64(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)
	_, err := sp.ParseResponse("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

func TestParseResponseMissingAssertion(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)

	samlResponseXML := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response123" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
</samlp:Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(samlResponseXML))
	_, err := sp.ParseResponse(encoded)
	if err == nil {
		t.Error("expected error for missing assertion, got nil")
	}
}

func TestGetRedirectURL(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)
	redirectURL := sp.GetRedirectURL()

	if !strings.Contains(redirectURL, "SAMLRequest=") {
		t.Error("redirect URL should contain SAMLRequest parameter")
	}
	if !strings.Contains(redirectURL, "https://idp.example.com/saml?") {
		t.Errorf("redirect URL should use IdP URL, got %s", redirectURL)
	}
}

func TestGetRedirectURLWithMetadataPath(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml/metadata",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)
	redirectURL := sp.GetRedirectURL()

	if strings.Contains(redirectURL, "/metadata?") {
		t.Error("redirect URL should strip /metadata path")
	}
	if !strings.Contains(redirectURL, "https://idp.example.com/saml?") {
		t.Errorf("redirect URL should use base IdP URL, got %s", redirectURL)
	}
}

func TestSAMLMiddlewareRequireAuth(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)
	middleware := NewSAMLMiddleware(sp, MiddlewareConfig{
		SessionKey:   "test_session",
		RedirectPath: "/login",
		SkipPaths:   []string{"/health", "/public"},
	})

	app := fiber.New()
	app.Use(middleware.RequireAuth())
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}

	if resp.StatusCode != fiber.StatusFound {
		t.Errorf("expected redirect (302), got %d", resp.StatusCode)
	}
}

func TestSAMLMiddlewareRequireAuthWithSkipPath(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)
	middleware := NewSAMLMiddleware(sp, MiddlewareConfig{
		SessionKey:   "test_session",
		RedirectPath: "/login",
		SkipPaths:    []string{"/health"},
	})

	app := fiber.New()
	app.Use(middleware.RequireAuth())
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("healthy")
	})

	req := httptest.NewRequest("GET", "/health", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("expected 200 for skipped path, got %d", resp.StatusCode)
	}
}

func TestSAMLMiddlewareRequireAuthWithValidToken(t *testing.T) {
	sessionKey := "test_session_key_12345"

	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)
	middleware := NewSAMLMiddleware(sp, MiddlewareConfig{
		SessionKey:   sessionKey,
		RedirectPath: "/login",
	})

	claims := jwt.MapClaims{
		"sub":   "user@example.com",
		"email":  "user@example.com",
		"groups": []string{"admin"},
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(1 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(sessionKey))
	if err != nil {
		t.Fatalf("sign token error: %v", err)
	}

	app := fiber.New()
	app.Use(middleware.RequireAuth())
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("expected 200 with valid token, got %d", resp.StatusCode)
	}
}

func TestSAMLMiddlewareHandleACS(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)
	middleware := NewSAMLMiddleware(sp, MiddlewareConfig{
		SessionKey:   "test_session",
		RedirectPath: "/login",
	})

	app := fiber.New()
	app.Post("/saml/acs", middleware.HandleACS())

	req := httptest.NewRequest("POST", "/saml/acs", strings.NewReader("SAMLResponse=invalid"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}

	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Errorf("expected 401 for invalid SAML response, got %d", resp.StatusCode)
	}
}

func TestSAMLMiddlewareHandleACSMissingResponse(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)
	middleware := NewSAMLMiddleware(sp, MiddlewareConfig{
		SessionKey:   "test_session",
		RedirectPath: "/login",
	})

	app := fiber.New()
	app.Post("/saml/acs", middleware.HandleACS())

	req := httptest.NewRequest("POST", "/saml/acs", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}

	if resp.StatusCode != fiber.StatusBadRequest {
		t.Errorf("expected 400 for missing SAMLResponse, got %d", resp.StatusCode)
	}
}

func TestSAMLMiddlewareHandleMetadata(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)
	middleware := NewSAMLMiddleware(sp, MiddlewareConfig{
		SessionKey:   "test_session",
		RedirectPath: "/login",
	})

	app := fiber.New()
	app.Get("/saml/metadata", middleware.HandleMetadata())

	req := httptest.NewRequest("GET", "/saml/metadata", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body := make([]byte, resp.ContentLength)
	resp.Body.Read(body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "EntityDescriptor") {
		t.Error("metadata should contain EntityDescriptor element")
	}
	if !strings.Contains(bodyStr, config.SPEntityID) {
		t.Error("metadata should contain SP entity ID")
	}
	if !strings.Contains(bodyStr, config.AcsURL) {
		t.Error("metadata should contain ACS URL")
	}
}

func TestNewSAMLMiddlewareDefaults(t *testing.T) {
	config := SAMLConfig{
		IDPMetadataURL: "https://idp.example.com/saml",
		IDPEntityID:    "https://idp.example.com",
		SPEntityID:     "https://sp.example.com",
		AcsURL:         "https://sp.example.com/saml/acs",
	}

	sp := NewSAMLServiceProvider(config)
	middleware := NewSAMLMiddleware(sp, MiddlewareConfig{})

	if middleware.config.SessionKey != "saml_session" {
		t.Errorf("expected default SessionKey 'saml_session', got %s", middleware.config.SessionKey)
	}
	if middleware.config.RedirectPath != "/auth/login" {
		t.Errorf("expected default RedirectPath '/auth/login', got %s", middleware.config.RedirectPath)
	}
}

func TestSAMLXMLUnmarshal(t *testing.T) {
	xmlStr := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test123" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion123" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">test@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z"/>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z" SessionIndex="_session456"/>
  </saml:Assertion>
</samlp:Response>`

	var response SAMLResponseDoc
	err := xml.Unmarshal([]byte(xmlStr), &response)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if response.Assertion == nil {
		t.Fatal("expected assertion to be parsed")
	}
	if response.Assertion.Issuer == nil || response.Assertion.Issuer.Value != "https://idp.example.com" {
		t.Error("expected issuer value")
	}
	if response.Assertion.Subject == nil || response.Assertion.Subject.NameID == nil {
		t.Error("expected subject with NameID")
	}
	if response.Assertion.Subject.NameID.Value != "test@example.com" {
		t.Errorf("expected NameID 'test@example.com', got %s", response.Assertion.Subject.NameID.Value)
	}
}