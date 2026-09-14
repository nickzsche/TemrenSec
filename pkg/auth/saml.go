package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// SAMLConfig holds the configuration for a SAML Service Provider.
type SAMLConfig struct {
	IDPMetadataURL string
	IDPEntityID    string
	SPEntityID     string
	AcsURL         string
	Certificate    string
	PrivateKey     string
}

// SAMLServiceProvider implements SAML authentication operations.
type SAMLServiceProvider struct {
	config      SAMLConfig
	cert       *x509.Certificate
	privateKey *rsa.PrivateKey
}

// SAMLAssertion represents a parsed SAML assertion with user attributes.
type SAMLAssertion struct {
	Subject      string
	NameID       string
	Email        string
	Groups       []string
	Issuer       string
	NotBefore    time.Time
	NotOnOrAfter time.Time
	SessionIndex string
}

// NewSAMLServiceProvider creates a new SAML service provider from the given config.
func NewSAMLServiceProvider(config SAMLConfig) *SAMLServiceProvider {
	sp := &SAMLServiceProvider{
		config: config,
	}

	if config.Certificate != "" {
		if cert, err := parseCertificate(config.Certificate); err == nil {
			sp.cert = cert
		}
	}

	if config.PrivateKey != "" {
		if key, err := parsePrivateKey(config.PrivateKey); err == nil {
			sp.privateKey = key
		}
	}

	return sp
}

// GenerateAuthRequest generates a base64-encoded SAML AuthnRequest XML.
func (sp *SAMLServiceProvider) GenerateAuthRequest() (string, error) {
	id := "_" + uuid.New().String()
	issueInstant := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	envelope := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s">
  <saml:Issuer>%s</saml:Issuer>
</samlp:AuthnRequest>`,
		id, issueInstant, sp.config.IDPMetadataURL, sp.config.AcsURL, sp.config.SPEntityID)

	return base64.StdEncoding.EncodeToString([]byte(envelope)), nil
}

// ParseResponse validates and parses a base64-encoded SAML response.
func (sp *SAMLServiceProvider) ParseResponse(samlResponse string) (*SAMLAssertion, error) {
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("decode saml response: %w", err)
	}

	var response SAMLResponseDoc
	if err := xml.Unmarshal(decoded, &response); err != nil {
		return nil, fmt.Errorf("unmarshal saml response: %w", err)
	}

	if response.Assertion == nil {
		return nil, fmt.Errorf("saml response missing assertion")
	}

	assertion := response.Assertion

	now := time.Now().UTC()
	if !assertion.Conditions.NotBefore.IsZero() && now.Before(assertion.Conditions.NotBefore) {
		return nil, fmt.Errorf("saml assertion not yet valid (not before: %s)", assertion.Conditions.NotBefore)
	}
	if !assertion.Conditions.NotOnOrAfter.IsZero() && !now.Before(assertion.Conditions.NotOnOrAfter) {
		return nil, fmt.Errorf("saml assertion expired (not on or after: %s)", assertion.Conditions.NotOnOrAfter)
	}

	nameID := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		nameID = assertion.Subject.NameID.Value
	}

	email := ""
	groups := []string{}
	for _, attrStmt := range assertion.AttributeStatements {
		for _, attr := range attrStmt.Attributes {
			switch attr.Name {
			case "email", "EmailAddress", "urn:oid:0.9.2342.19200300.100.1.3":
				if len(attr.Values) > 0 {
					email = attr.Values[0].Value
				}
			case "groups", "Group", "memberOf", "urn:oid:1.3.6.1.4.1.5923.1.1.1.1":
				for _, v := range attr.Values {
					groups = append(groups, v.Value)
				}
			}
		}
	}

	if email == "" && nameID != "" && strings.Contains(nameID, "@") {
		email = nameID
	}

	return &SAMLAssertion{
		Subject:      nameID,
		NameID:       nameID,
		Email:        email,
		Groups:       groups,
		Issuer:       assertion.Issuer.Value,
		NotBefore:    assertion.Conditions.NotBefore,
		NotOnOrAfter: assertion.Conditions.NotOnOrAfter,
		SessionIndex: assertion.AuthnStatement.SessionIndex,
	}, nil
}

// GetRedirectURL returns the IdP redirect URL with the SAMLRequest parameter.
func (sp *SAMLServiceProvider) GetRedirectURL() string {
	authRequest, err := sp.GenerateAuthRequest()
	if err != nil {
		return ""
	}

	params := url.Values{}
	params.Set("SAMLRequest", authRequest)

	idpURL := sp.config.IDPMetadataURL
	if strings.Contains(idpURL, "/metadata") {
		idpURL = strings.Replace(idpURL, "/metadata", "", 1)
	}

	if strings.Contains(idpURL, "?") {
		return idpURL + "&" + params.Encode()
	}
	return idpURL + "?" + params.Encode()
}

// MiddlewareConfig holds configuration for the SAML middleware.
type MiddlewareConfig struct {
	SessionKey   string
	RedirectPath string
	SkipPaths   []string
}

// SAMLMiddleware provides Fiber v2 middleware for SAML authentication.
type SAMLMiddleware struct {
	sp     *SAMLServiceProvider
	config MiddlewareConfig
}

// NewSAMLMiddleware creates a new SAML middleware instance.
func NewSAMLMiddleware(sp *SAMLServiceProvider, config MiddlewareConfig) *SAMLMiddleware {
	if config.SessionKey == "" {
		config.SessionKey = "saml_session"
	}
	if config.RedirectPath == "" {
		config.RedirectPath = "/auth/login"
	}
	return &SAMLMiddleware{
		sp:     sp,
		config: config,
	}
}

// RequireAuth returns a Fiber middleware handler that validates SAML session cookie/token.
func (m *SAMLMiddleware) RequireAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		for _, path := range m.config.SkipPaths {
			if c.Path() == path {
				return c.Next()
			}
		}

		sessionToken := c.Cookies(m.config.SessionKey)
		if sessionToken == "" {
			sessionToken = c.Get("Authorization")
			sessionToken = strings.TrimPrefix(sessionToken, "Bearer ")
		}

		if sessionToken == "" {
			return c.Redirect(m.config.RedirectPath)
		}

		token, err := jwt.Parse(sessionToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(m.config.SessionKey), nil
		})

		if err != nil || !token.Valid {
			return c.Redirect(m.config.RedirectPath)
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Locals("saml_user", claims)
		}

		return c.Next()
	}
}

// HandleACS returns a Fiber handler that processes SAML responses at the ACS endpoint.
func (m *SAMLMiddleware) HandleACS() fiber.Handler {
	return func(c *fiber.Ctx) error {
		samlResponse := c.FormValue("SAMLResponse")
		if samlResponse == "" {
			samlResponse = c.Query("SAMLResponse")
		}

		if samlResponse == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "missing SAMLResponse parameter",
			})
		}

		assertion, err := m.sp.ParseResponse(samlResponse)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": fmt.Sprintf("saml response validation failed: %v", err),
			})
		}

		claims := jwt.MapClaims{
			"sub":   assertion.NameID,
			"email":  assertion.Email,
			"groups": assertion.Groups,
			"iss":    assertion.Issuer,
			"sid":    assertion.SessionIndex,
			"iat":    time.Now().Unix(),
			"exp":    time.Now().Add(8 * time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(m.config.SessionKey))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to create session token",
			})
		}

		c.Cookie(&fiber.Cookie{
			Name:     m.config.SessionKey,
			Value:    tokenString,
			MaxAge:   28800,
			Path:     "/",
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Lax",
		})

		return c.JSON(fiber.Map{
			"token":    tokenString,
			"name_id":  assertion.NameID,
			"email":    assertion.Email,
			"groups":   assertion.Groups,
			"issuer":   assertion.Issuer,
		})
	}
}

// HandleMetadata returns a Fiber handler that serves SP metadata XML.
func (m *SAMLMiddleware) HandleMetadata() fiber.Handler {
	return func(c *fiber.Ctx) error {
		metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`,
			m.sp.config.SPEntityID, m.sp.config.AcsURL)

		c.Set("Content-Type", "application/xml")
		return c.SendString(metadata)
	}
}

// SAMLResponseDoc represents a SAML Response XML document.
type SAMLResponseDoc struct {
	XMLName    xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	Destination string           `xml:"Destination,attr"`
	ID          string           `xml:"ID,attr"`
	IssueInstant string          `xml:"IssueInstant,attr"`
	Assertion   *SAMLAssertionDoc `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

// SAMLAssertionDoc represents a SAML Assertion element.
type SAMLAssertionDoc struct {
	XMLName            xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string                `xml:"ID,attr"`
	IssueInstant       string                `xml:"IssueInstant,attr"`
	Issuer            *SAMLIssuerDoc         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject           *SAMLSubjectDoc        `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions        SAMLConditionsDoc      `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AuthnStatement    SAMLAuthnStatementDoc  `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AttributeStatements []SAMLAttributeStatementDoc `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

// SAMLIssuerDoc represents a SAML Issuer element.
type SAMLIssuerDoc struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

// SAMLSubjectDoc represents a SAML Subject element.
type SAMLSubjectDoc struct {
	XMLName xml.Name       `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID  *SAMLNameIDDoc `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
}

// SAMLNameIDDoc represents a SAML NameID element.
type SAMLNameIDDoc struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Format  string   `xml:"Format,attr"`
	Value   string   `xml:",chardata"`
}

// SAMLConditionsDoc represents SAML Conditions.
type SAMLConditionsDoc struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	NotBefore    time.Time `xml:"NotBefore,attr"`
	NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr"`
}

// SAMLAuthnStatementDoc represents a SAML AuthnStatement.
type SAMLAuthnStatementDoc struct {
	XMLName       xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AuthnInstant  string   `xml:"AuthnInstant,attr"`
	SessionIndex  string   `xml:"SessionIndex,attr"`
}

// SAMLAttributeStatementDoc represents a SAML AttributeStatement.
type SAMLAttributeStatementDoc struct {
	XMLName    xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
	Attributes []SAMLAttributeDoc   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// SAMLAttributeDoc represents a SAML Attribute.
type SAMLAttributeDoc struct {
	XMLName xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	Name    string            `xml:"Name,attr"`
	Values []SAMLAttributeValueDoc `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

// SAMLAttributeValueDoc represents a SAML AttributeValue.
type SAMLAttributeValueDoc struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
	Value   string   `xml:",chardata"`
}

// parseCertificate parses a PEM-encoded X.509 certificate.
func parseCertificate(pemData string) (*x509.Certificate, error) {
	block, _ := pemDecode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parsePrivateKey parses a PEM-encoded RSA private key.
func parsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pemDecode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return key.(*rsa.PrivateKey), nil
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return rsaKey, nil
}

func pemDecode(data string) (*pemBlock, []byte) {
	data = strings.TrimSpace(data)

	if strings.HasPrefix(data, "-----BEGIN") {
		lines := strings.Split(data, "\n")
		var b64Lines []string
		inBlock := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "-----BEGIN") {
				inBlock = true
				continue
			}
			if strings.HasPrefix(line, "-----END") {
				inBlock = false
				continue
			}
			if inBlock && line != "" {
				b64Lines = append(b64Lines, line)
			}
		}

		decoded, err := base64.StdEncoding.DecodeString(strings.Join(b64Lines, ""))
		if err != nil {
			return nil, nil
		}
		return &pemBlock{Bytes: decoded}, decoded
	}

	rawDecoded, rawErr := base64.StdEncoding.DecodeString(data)
	if rawErr != nil {
		return nil, nil
	}
	return &pemBlock{Bytes: rawDecoded}, rawDecoded
}

type pemBlock struct {
	Bytes []byte
}