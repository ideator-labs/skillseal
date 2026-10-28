package main

import (
	"crypto/ed25519"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestSealVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	skill := filepath.Join(dir, "invoice-reconcile")
	if err := copyTree("fixtures/invoice-reconcile", skill); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := BuildSeal(skill, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteSeal(skill, s); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSeal(filepath.Join(skill, SealFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(loaded); err != nil {
		t.Fatal(err)
	}
	diff, err := Compare(loaded, skill)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Empty() {
		t.Fatalf("expected empty diff, got %+v", diff)
	}
}

func TestTamperDetected(t *testing.T) {
	dir := t.TempDir()
	skill := filepath.Join(dir, "invoice-reconcile")
	if err := copyTree("fixtures/invoice-reconcile", skill); err != nil {
		t.Fatal(err)
	}
	s, err := BuildSeal(skill, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteSeal(skill, s); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(skill, "scripts", "check.py")
	b, _ := os.ReadFile(p)
	_ = os.WriteFile(p, append(b, []byte("\n# evil\n")...), 0o644)
	diff, err := Compare(s, skill)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Changed) != 1 || diff.Changed[0].Path != "scripts/check.py" {
		t.Fatalf("expected scripts/check.py changed, got %+v", diff)
	}
}

func TestNameDirectoryMismatch(t *testing.T) {
	dir := t.TempDir()
	skill := filepath.Join(dir, "wrong-name")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: invoice-reconcile\ndescription: x\n---\n\nbody\n"), 0o644)
	_, err := BuildSeal(skill, nil)
	if err == nil {
		t.Fatal("expected name/dir mismatch error")
	}
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}
