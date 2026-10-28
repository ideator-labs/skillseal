package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SpecVersion is the SkillSeal document version. Aligns with MCP SEP-2640
// integrity fields (digest + size) for filesystem Agent Skills folders.
const SpecVersion = "skillseal/0.1"

// Seal is the pinned inventory of a skill directory.
// Digests establish consistency with the publisher's seal, not trust in content
// (same claim as MCP SEP-2640 overview).
type Seal struct {
	SpecVersion string      `json:"specVersion"`
	Name        string      `json:"name"`
	SealedAt    string      `json:"sealedAt"`
	Files       []FileEntry `json:"files"`
	// Signature is optional Ed25519 over CanonicalBytes(Files). Hex-encoded.
	// Publisher is the matching public key, also hex.
	Publisher string `json:"publisher,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// FileEntry mirrors SEP-2640 resource integrity: path (relative), digest, size.
type FileEntry struct {
	Path   string `json:"path"`
	Digest string `json:"digest"` // sha256:<64 lowercase hex>
	Size   int64  `json:"size"`
}

const SealFileName = "skill.seal.json"

// SealExcluded names that must never be hashed into the seal (the seal itself,
// VCS, and break-mode scratch).
var SealExcluded = map[string]bool{
	SealFileName: true,
	".git":       true,
	".demo":      true,
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func walkSkill(root string) ([]FileEntry, error) {
	var out []FileEntry
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		base := filepath.Base(path)
		if d.IsDir() {
			if SealExcluded[base] || SealExcluded[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		if SealExcluded[base] || SealExcluded[rel] {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out = append(out, FileEntry{
			Path:   rel,
			Digest: digestOf(b),
			Size:   int64(len(b)),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// CanonicalBytes is the stable bytes signed: sorted path\0digest\0size\n lines.
func CanonicalBytes(files []FileEntry) []byte {
	var b strings.Builder
	for _, f := range files {
		fmt.Fprintf(&b, "%s\x00%s\x00%d\n", f.Path, f.Digest, f.Size)
	}
	return []byte(b.String())
}

func readFrontmatterName(skillDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(skillDir, "SKILL.md"))
	if err != nil {
		return "", fmt.Errorf("SKILL.md required: %w", err)
	}
	text := string(b)
	if !strings.HasPrefix(text, "---") {
		return "", fmt.Errorf("SKILL.md missing YAML frontmatter")
	}
	rest := text[3:]
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return "", fmt.Errorf("SKILL.md frontmatter not closed")
	}
	fm := rest[:end]
	name := ""
	desc := ""
	for _, line := range strings.Split(fm, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
			name = strings.Trim(name, `"'`)
		}
		if strings.HasPrefix(line, "description:") {
			desc = strings.TrimSpace(strings.TrimPrefix(line, "description:"))
			desc = strings.Trim(desc, `"'`)
		}
	}
	if name == "" {
		return "", fmt.Errorf("frontmatter missing required field: name")
	}
	if desc == "" {
		return "", fmt.Errorf("frontmatter missing required field: description")
	}
	dirName := filepath.Base(filepath.Clean(skillDir))
	if dirName != name {
		return "", fmt.Errorf("directory name %q must match skill name %q", dirName, name)
	}
	if len(name) > 64 {
		return "", fmt.Errorf("name exceeds 64 characters")
	}
	if len(desc) > 1024 {
		return "", fmt.Errorf("description exceeds 1024 characters")
	}
	return name, nil
}

func BuildSeal(skillDir string, priv ed25519.PrivateKey) (*Seal, error) {
	name, err := readFrontmatterName(skillDir)
	if err != nil {
		return nil, err
	}
	files, err := walkSkill(skillDir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no files found under %s", skillDir)
	}
	s := &Seal{
		SpecVersion: SpecVersion,
		Name:        name,
		SealedAt:    time.Now().UTC().Format(time.RFC3339),
		Files:       files,
	}
	if priv != nil {
		pub := priv.Public().(ed25519.PublicKey)
		s.Publisher = hex.EncodeToString(pub)
		sig := ed25519.Sign(priv, CanonicalBytes(files))
		s.Signature = hex.EncodeToString(sig)
	}
	return s, nil
}

func WriteSeal(skillDir string, s *Seal) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(filepath.Join(skillDir, SealFileName), b, 0o644)
}

func LoadSeal(path string) (*Seal, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Seal
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.SpecVersion == "" {
		return nil, fmt.Errorf("missing specVersion")
	}
	return &s, nil
}

// Diff lists mismatches between a seal and the live tree.
type Diff struct {
	Missing  []string    // in seal, not on disk
	Extra    []string    // on disk, not in seal
	Changed  []FileEntry // path present but digest or size differs (live values)
	Expected []FileEntry // matching seal entries for Changed
}

func (d Diff) Empty() bool {
	return len(d.Missing) == 0 && len(d.Extra) == 0 && len(d.Changed) == 0
}

func Compare(seal *Seal, skillDir string) (Diff, error) {
	live, err := walkSkill(skillDir)
	if err != nil {
		return Diff{}, err
	}
	byPath := map[string]FileEntry{}
	for _, f := range seal.Files {
		byPath[f.Path] = f
	}
	livePath := map[string]FileEntry{}
	for _, f := range live {
		livePath[f.Path] = f
	}
	var d Diff
	for p, want := range byPath {
		got, ok := livePath[p]
		if !ok {
			d.Missing = append(d.Missing, p)
			continue
		}
		if got.Digest != want.Digest || got.Size != want.Size {
			d.Changed = append(d.Changed, got)
			d.Expected = append(d.Expected, want)
		}
	}
	for p := range livePath {
		if _, ok := byPath[p]; !ok {
			d.Extra = append(d.Extra, p)
		}
	}
	sort.Strings(d.Missing)
	sort.Strings(d.Extra)
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].Path < d.Changed[j].Path })
	sort.Slice(d.Expected, func(i, j int) bool { return d.Expected[i].Path < d.Expected[j].Path })
	return d, nil
}

func VerifySignature(seal *Seal) error {
	if seal.Signature == "" && seal.Publisher == "" {
		return nil
	}
	if seal.Signature == "" || seal.Publisher == "" {
		return fmt.Errorf("signature and publisher must both be set or both omitted")
	}
	pub, err := hex.DecodeString(seal.Publisher)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid publisher public key")
	}
	sig, err := hex.DecodeString(seal.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), CanonicalBytes(seal.Files), sig) {
		return fmt.Errorf("signature does not match files inventory")
	}
	return nil
}
