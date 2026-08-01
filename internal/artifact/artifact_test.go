package artifact

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteDeterministicZipIsByteIdentical(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(filepath.Join(source, "z"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "b.txt"), []byte("beta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "z", "a.txt"), []byte("alpha\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(t.TempDir(), "first.zip")
	second := filepath.Join(t.TempDir(), "second.zip")
	if err := WriteDeterministicZip(source, first, "h1-racer-v1"); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(48 * time.Hour)
	if err := os.Chtimes(filepath.Join(source, "b.txt"), future, future); err != nil {
		t.Fatal(err)
	}
	if err := WriteDeterministicZip(source, second, "h1-racer-v1"); err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := os.ReadFile(first)
	secondBytes, _ := os.ReadFile(second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("deterministic archives differ")
	}
	reader, err := zip.OpenReader(first)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if len(reader.File) != 2 || reader.File[0].Name != "h1-racer-v1/b.txt" ||
		reader.File[1].Name != "h1-racer-v1/z/a.txt" {
		t.Fatalf("archive order = %+v", reader.File)
	}
	for _, file := range reader.File {
		if !file.Modified.Equal(fixedArchiveTime) {
			t.Fatalf("entry %s timestamp = %s", file.Name, file.Modified)
		}
	}
}

func TestSignVerifyAndTamper(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	privatePath := filepath.Join(root, "private.pem")
	publicPath := filepath.Join(root, "public.pem")
	subjectPath := filepath.Join(root, "release.zip")
	signaturePath := filepath.Join(root, "release.zip.sig.json")
	if err = os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(subjectPath, []byte("release bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = SignFile(subjectPath, privatePath, signaturePath); err != nil {
		t.Fatal(err)
	}
	firstSignature, _ := os.ReadFile(signaturePath)
	if err = SignFile(subjectPath, privatePath, signaturePath); err != nil {
		t.Fatal(err)
	}
	secondSignature, _ := os.ReadFile(signaturePath)
	if !bytes.Equal(firstSignature, secondSignature) {
		t.Fatal("Ed25519 signature record is not deterministic")
	}
	if err = VerifyFile(subjectPath, publicPath, signaturePath); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(subjectPath, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = VerifyFile(subjectPath, publicPath, signaturePath); err == nil {
		t.Fatal("tampered release verified")
	}
}

func TestGenerateKeyPairRefusesOverwrite(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "private.pem")
	publicPath := filepath.Join(root, "public.pem")
	if err := GenerateKeyPair(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	if err := GenerateKeyPair(privatePath, publicPath); err == nil {
		t.Fatal("key generation overwrote an existing key")
	}
}
