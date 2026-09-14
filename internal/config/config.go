package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	Port        string
	DatabaseURL string
	RedisURL    string
	JWTSecret   string
	JWTExpiry   string
	Environment string
	FrontendURL string

	SMTPHost string
	SMTPPort string
	SMTPUser string
	SMTPPass string
	SMTPFrom string

	WorkerConcurrency int
	ScanTimeout       int

	SlackWebhookURL   string
	DiscordWebhookURL string
	WebhookSecret     string

	FreePlanTargets int
	ProPlanTargets  int
	TeamPlanTargets int
	FreePlanScans   int
	ProPlanScans    int
	TeamPlanScans   int
}

var AppConfig *Config

func Load() *Config {
	_ = godotenv.Load()

	jwtSecret := getEnv("JWT_SECRET", "change-me-in-production-please")
	
	if err := ValidateJWTSecret(jwtSecret); err != nil {
		if isProduction() {
			log.Fatalf("[FATAL] JWT_SECRET validation failed: %v", err)
		} else {
			log.Printf("[WARN] JWT_SECRET validation: %v", err)
		}
	}

	AppConfig = &Config{
		Port:        getEnv("PORT", "8080"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://temren:temren@localhost:5432/temren?sslmode=disable"),
		RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379"),
		JWTSecret:   jwtSecret,
		JWTExpiry:   getEnv("JWT_EXPIRY", "24h"),
		Environment: getEnv("ENVIRONMENT", "development"),
		FrontendURL: getEnv("FRONTEND_URL", "http://localhost:3000"),

		SMTPHost: getEnv("SMTP_HOST", ""),
		SMTPPort: getEnv("SMTP_PORT", "587"),
		SMTPUser: getEnv("SMTP_USER", ""),
		SMTPPass: getEnv("SMTP_PASS", ""),
		SMTPFrom: getEnv("SMTP_FROM", ""),

		WorkerConcurrency: getEnvInt("WORKER_CONCURRENCY", 5),
		ScanTimeout:       getEnvInt("SCAN_TIMEOUT", 30),

		SlackWebhookURL:   getEnv("SLACK_WEBHOOK_URL", ""),
		DiscordWebhookURL: getEnv("DISCORD_WEBHOOK_URL", ""),
		WebhookSecret:     getEnv("WEBHOOK_SECRET", ""),

		FreePlanTargets: getEnvInt("FREE_PLAN_TARGETS", 1),
		ProPlanTargets:  getEnvInt("PRO_PLAN_TARGETS", 5),
		TeamPlanTargets: getEnvInt("TEAM_PLAN_TARGETS", 20),
		FreePlanScans:   getEnvInt("FREE_PLAN_SCANS", 5),
		ProPlanScans:    getEnvInt("PRO_PLAN_SCANS", 50),
		TeamPlanScans:   getEnvInt("TEAM_PLAN_SCANS", 200),
	}

	return AppConfig
}

func isProduction() bool {
	env := strings.ToLower(os.Getenv("ENVIRONMENT"))
	return env == "production" || env == "prod"
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	var result int
	for _, c := range val {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		} else {
			return fallback
		}
	}
	return result
}

var insecureSecrets = []string{
	"change-me-in-production-please",
	"secret",
	"password",
	"123456",
	"admin",
	"default",
	"test",
	"changeme",
}

func ValidateJWTSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("JWT_SECRET cannot be empty")
	}

	if len(secret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters long (current: %d)", len(secret))
	}

	lowerSecret := strings.ToLower(secret)
	for _, insecure := range insecureSecrets {
		if strings.Contains(lowerSecret, insecure) {
			return fmt.Errorf("JWT_SECRET contains insecure value: %s", insecure)
		}
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, c := range secret {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 33 && c <= 126:
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("JWT_SECRET must contain uppercase, lowercase, and digits")
	}

	if !hasSpecial {
		log.Printf("[WARN] JWT_SECRET should contain special characters for better security")
	}

	return nil
}
