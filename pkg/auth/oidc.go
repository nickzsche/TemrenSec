package auth

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// OIDCConfig holds the configuration for an OpenID Connect provider.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// OIDCProvider implements OpenID Connect authentication operations.
type OIDCProvider struct {
	config     OIDCConfig
	httpClient *http.Client
}

// OIDCToken represents the tokens and claims from an OIDC flow.
type OIDCToken struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	Expiry       time.Time
	Email        string
	Name         string
	Groups       []string
}

// NewOIDCProvider creates a new OIDC provider from the given config.
func NewOIDCProvider(config OIDCConfig) *OIDCProvider {
	if len(config.Scopes) == 0 {
		config.Scopes = []string{"openid", "profile", "email"}
	}
	return &OIDCProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetAuthorizationURL returns the OIDC authorization URL with the given state parameter.
func (p *OIDCProvider) GetAuthorizationURL(state string) string {
	scopes := strings.Join(p.config.Scopes, " ")

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", p.config.RedirectURL)
	params.Set("scope", scopes)
	params.Set("state", state)
	params.Set("nonce", uuid.New().String())

	authURL := strings.TrimRight(p.config.IssuerURL, "/") + "/authorize"
	return authURL + "?" + params.Encode()
}

// ExchangeCode exchanges an authorization code for OIDC tokens.
func (p *OIDCProvider) ExchangeCode(code string) (*OIDCToken, error) {
	tokenURL := strings.TrimRight(p.config.IssuerURL, "/") + "/token"

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", p.config.RedirectURL)
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errBody)
		return nil, fmt.Errorf("token exchange failed with status %d: %v", resp.StatusCode, errBody)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	token := &OIDCToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		Expiry:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

	if tokenResp.IDToken != "" {
		p.parseIDTokenClaims(tokenResp.IDToken, token)
	}

	return token, nil
}

// RefreshToken refreshes an OIDC token using a refresh token.
func (p *OIDCProvider) RefreshToken(refreshToken string) (*OIDCToken, error) {
	tokenURL := strings.TrimRight(p.config.IssuerURL, "/") + "/token"

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errBody)
		return nil, fmt.Errorf("token refresh failed with status %d: %v", resp.StatusCode, errBody)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode refresh response: %w", err)
	}

	token := &OIDCToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		Expiry:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

	if tokenResp.IDToken != "" {
		p.parseIDTokenClaims(tokenResp.IDToken, token)
	}

	return token, nil
}

// parseIDTokenClaims extracts claims from an ID token JWT without signature verification.
func (p *OIDCProvider) parseIDTokenClaims(idToken string, token *OIDCToken) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(padBase64(parts[1]))
		if err != nil {
			return
		}
	}

	var claims struct {
		Email  string   `json:"email"`
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return
	}

	token.Email = claims.Email
	token.Name = claims.Name
	token.Groups = claims.Groups
}

// GenerateState generates a cryptographically random state parameter for OIDC flows.
func GenerateState() string {
	return uuid.New().String()
}

// ValidateState validates an OIDC state parameter against the original using HMAC.
func ValidateState(state, original string) bool {
	return hmac.Equal([]byte(state), []byte(original))
}

// padBase64 adds base64 padding if needed.
func padBase64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
case 3:
		return s + "="
	default:
		return s
	}
}