package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func usage() {
	fmt.Fprintf(os.Stderr, `skillseal: pin Agent Skills folders with SEP-2640-style digests

Usage:
  skillseal seal   <skill-dir> [--key <ed25519-seed-hex>]
  skillseal verify <skill-dir> [--ignore-digest] [--require-signature]
  skillseal show   <skill-dir>
  skillseal keygen

Exit codes: 0 ok, 1 integrity failure, 2 bad input
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "seal":
		os.Exit(cmdSeal(os.Args[2:]))
	case "verify":
		os.Exit(cmdVerify(os.Args[2:]))
	case "show":
		os.Exit(cmdShow(os.Args[2:]))
	case "keygen":
		os.Exit(cmdKeygen())
	default:
		usage()
		os.Exit(2)
	}
}

func cmdKeygen() int {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Printf("public=%s\nseed=%s\n", hex.EncodeToString(pub), hex.EncodeToString(priv.Seed()))
	return 0
}

func parseKey(args []string) (ed25519.PrivateKey, []string, error) {
	out := args
	var priv ed25519.PrivateKey
	for i := 0; i < len(out); i++ {
		if out[i] == "--key" && i+1 < len(out) {
			seed, err := hex.DecodeString(out[i+1])
			if err != nil || len(seed) != ed25519.SeedSize {
				return nil, nil, fmt.Errorf("--key must be 32-byte seed hex")
			}
			priv = ed25519.NewKeyFromSeed(seed)
			out = append(out[:i], out[i+2:]...)
			return priv, out, nil
		}
	}
	return nil, out, nil
}

func cmdSeal(args []string) int {
	priv, args, err := parseKey(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if len(args) != 1 {
		usage()
		return 2
	}
	dir := args[0]
	s, err := BuildSeal(dir, priv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := WriteSeal(dir, s); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Printf("sealed %s: %d files\n", s.Name, len(s.Files))
	for _, f := range s.Files {
		fmt.Printf("  %s  %d  %s\n", f.Digest, f.Size, f.Path)
	}
	if s.Signature != "" {
		fmt.Printf("signed by %s…\n", s.Publisher[:16])
	}
	return 0
}

func cmdVerify(args []string) int {
	ignore := false
	requireSig := false
	var dir string
	for _, a := range args {
		switch a {
		case "--ignore-digest":
			ignore = true
		case "--require-signature":
			requireSig = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "unknown flag %s\n", a)
				return 2
			}
			dir = a
		}
	}
	if dir == "" {
		usage()
		return 2
	}
	sealPath := filepath.Join(dir, SealFileName)
	seal, err := LoadSeal(sealPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if requireSig && seal.Signature == "" {
		fmt.Fprintln(os.Stderr, "seal has no signature (--require-signature)")
		return 1
	}
	if err := VerifySignature(seal); err != nil {
		fmt.Fprintln(os.Stderr, "signature:", err)
		return 1
	}
	// Frontmatter must still parse and match directory.
	if _, err := readFrontmatterName(dir); err != nil {
		fmt.Fprintln(os.Stderr, "frontmatter:", err)
		return 1
	}
	diff, err := Compare(seal, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if ignore {
		fmt.Println("BREAK: --ignore-digest (treating tree as matching seal; inventory not checked)")
		fmt.Printf("ok %s (%d files; inventory check skipped)\n", seal.Name, len(seal.Files))
		return 0
	}
	if !diff.Empty() {
		for _, p := range diff.Missing {
			fmt.Printf("MISSING %s\n", p)
		}
		for _, p := range diff.Extra {
			fmt.Printf("EXTRA %s\n", p)
		}
		for i, got := range diff.Changed {
			want := diff.Expected[i]
			fmt.Printf("CHANGED %s size=%d→%d digest %s→%s\n", got.Path, want.Size, got.Size, want.Digest, got.Digest)
		}
		fmt.Printf("FAIL %s: %d missing, %d extra, %d changed\n", seal.Name, len(diff.Missing), len(diff.Extra), len(diff.Changed))
		return 1
	}
	fmt.Printf("ok %s (%d files)\n", seal.Name, len(seal.Files))
	return 0
}

func cmdShow(args []string) int {
	if len(args) != 1 {
		usage()
		return 2
	}
	seal, err := LoadSeal(filepath.Join(args[0], SealFileName))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(seal)
	return 0
}
