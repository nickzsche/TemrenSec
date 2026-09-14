package report

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type EncryptedReport struct {
	ReportPath string
	Password   string
	Timestamp  string
}

type EncryptionService struct {
	key []byte
}

func NewEncryptionService(password string) (*EncryptionService, error) {
	key := sha256.Sum256([]byte(password))
	return &EncryptionService{
		key: key[:],
	}, nil
}

func (e *EncryptionService) EncryptFile(inputPath, outputPath string) error {
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	encrypted, err := e.Encrypt(inputData)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	return os.WriteFile(outputPath, encrypted, 0644)
}

func (e *EncryptionService) DecryptFile(inputPath, outputPath string) error {
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	decrypted, err := e.Decrypt(inputData)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	return os.WriteFile(outputPath, decrypted, 0644)
}

func (e *EncryptionService) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (e *EncryptionService) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func (r *Report) EncryptAndSave(filename, password string) error {
	html := r.GenerateHTML()

	enc, err := NewEncryptionService(password)
	if err != nil {
		return err
	}

	encrypted, err := enc.Encrypt([]byte(html))
	if err != nil {
		return err
	}

	ext := filepath.Ext(filename)
	baseName := strings.TrimSuffix(filename, ext)
	encryptedPath := baseName + ".enc"

	return os.WriteFile(encryptedPath, encrypted, 0644)
}

func DecryptReportFile(encryptedPath, password, outputPath string) error {
	enc, err := NewEncryptionService(password)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		return err
	}

	decrypted, err := enc.Decrypt(data)
	if err != nil {
		return fmt.Errorf("invalid password or corrupted file")
	}

	return os.WriteFile(outputPath, decrypted, 0644)
}

func GeneratePassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	password := make([]byte, length)

	if _, err := rand.Read(password); err != nil {
		return "", err
	}

	for i := range password {
		password[i] = charset[int(password[i])%len(charset)]
	}

	return base64.URLEncoding.EncodeToString(password)[:length], nil
}
