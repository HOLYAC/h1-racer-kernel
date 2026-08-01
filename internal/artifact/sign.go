package artifact

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const signatureDomain = "H1-RACER-RELEASE-SIGNATURE-V1\x00"

type Signature struct {
	SchemaVersion   int    `json:"schema_version"`
	Algorithm       string `json:"algorithm"`
	SubjectFile     string `json:"subject_file"`
	SubjectSHA256   string `json:"subject_sha256"`
	PublicKeySHA256 string `json:"public_key_sha256"`
	SignatureBase64 string `json:"signature_base64"`
}

func GenerateKeyPair(privatePath, publicPath string) error {
	if privatePath == "" || publicPath == "" {
		return errors.New("private and public key paths are required")
	}
	if _, err := os.Stat(privatePath); err == nil {
		return fmt.Errorf("private key already exists: %s", privatePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat private key: %w", err)
	}
	if _, err := os.Stat(publicPath); err == nil {
		return fmt.Errorf("public key already exists: %s", publicPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat public key: %w", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate Ed25519 key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err = writeNewFile(privatePath, privatePEM, 0o600); err != nil {
		return err
	}
	if err = writeNewFile(publicPath, publicPEM, 0o644); err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	return nil
}

func PublicKeyFingerprint(publicPath string) (string, error) {
	publicKey, err := readPublicKey(publicPath)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:]), nil
}

func SignFile(subjectPath, privatePath, signaturePath string) error {
	privateKey, err := readPrivateKey(privatePath)
	if err != nil {
		return err
	}
	subjectSize, digest, err := readSubject(subjectPath)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicDigest := sha256.Sum256(publicKey)
	signedPayload := signingPayload(digest)
	signatureBytes := ed25519.Sign(privateKey, signedPayload)
	record := Signature{
		SchemaVersion:   1,
		Algorithm:       "Ed25519-SHA256-DOMAIN-V1",
		SubjectFile:     filepath.Base(subjectPath),
		SubjectSHA256:   hex.EncodeToString(digest[:]),
		PublicKeySHA256: hex.EncodeToString(publicDigest[:]),
		SignatureBase64: base64.StdEncoding.EncodeToString(signatureBytes),
	}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode signature: %w", err)
	}
	encoded = append(encoded, '\n')
	if subjectSize == 0 {
		return errors.New("refusing to sign empty subject")
	}
	return writeAtomic(signaturePath, encoded, 0o644)
}

func VerifyFile(subjectPath, publicPath, signaturePath string) error {
	publicKey, err := readPublicKey(publicPath)
	if err != nil {
		return err
	}
	_, digest, err := readSubject(subjectPath)
	if err != nil {
		return err
	}
	encoded, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record Signature
	if err = decoder.Decode(&record); err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("signature contains multiple JSON values")
		}
		return fmt.Errorf("decode trailing signature data: %w", err)
	}
	if record.SchemaVersion != 1 || record.Algorithm != "Ed25519-SHA256-DOMAIN-V1" {
		return errors.New("unsupported signature schema or algorithm")
	}
	if record.SubjectFile != filepath.Base(subjectPath) {
		return fmt.Errorf("signature subject is %q, expected %q", record.SubjectFile, filepath.Base(subjectPath))
	}
	if record.SubjectSHA256 != hex.EncodeToString(digest[:]) {
		return errors.New("subject SHA-256 does not match signature record")
	}
	publicDigest := sha256.Sum256(publicKey)
	if record.PublicKeySHA256 != hex.EncodeToString(publicDigest[:]) {
		return errors.New("public key fingerprint does not match signature record")
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(record.SignatureBase64)
	if err != nil {
		return fmt.Errorf("decode Ed25519 signature: %w", err)
	}
	if !ed25519.Verify(publicKey, signingPayload(digest), signatureBytes) {
		return errors.New("Ed25519 signature verification failed")
	}
	return nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, remainder := pem.Decode(encoded)
	if block == nil || len(remainder) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("private key must be one PKCS#8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("private key is not Ed25519")
	}
	return privateKey, nil
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, remainder := pem.Decode(encoded)
	if block == nil || len(remainder) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errors.New("public key must be one PKIX PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("public key is not Ed25519")
	}
	return publicKey, nil
}

func readSubject(path string) (int64, [sha256.Size]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, [sha256.Size]byte{}, fmt.Errorf("read signed subject: %w", err)
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return 0, [sha256.Size]byte{}, fmt.Errorf("hash signed subject: %w", copyErr)
	}
	if closeErr != nil {
		return 0, [sha256.Size]byte{}, fmt.Errorf("close signed subject: %w", closeErr)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return size, digest, nil
}

func signingPayload(digest [sha256.Size]byte) []byte {
	payload := make([]byte, 0, len(signatureDomain)+len(digest))
	payload = append(payload, signatureDomain...)
	payload = append(payload, digest[:]...)
	return payload
}

func writeNewFile(path string, value []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create key parent: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	if _, err = file.Write(value); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write key file: %w", err)
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync key file: %w", err)
	}
	if err = file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close key file: %w", err)
	}
	return nil
}

func writeAtomic(path string, value []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output parent: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".h1-racer-signature-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary signature: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(mode); err != nil {
		return fmt.Errorf("set signature mode: %w", err)
	}
	if _, err = temporary.Write(value); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}
	if err = temporary.Sync(); err != nil {
		return fmt.Errorf("sync signature: %w", err)
	}
	if err = temporary.Close(); err != nil {
		return fmt.Errorf("close signature: %w", err)
	}
	if err = replaceFile(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}
