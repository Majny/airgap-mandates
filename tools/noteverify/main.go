// noteverify verifies a signed note (C2SP signed-note / tlog-checkpoint) using ONLY the unmodified
// golang.org/x/mod/sumdb/note package. Usage: noteverify <note-file|-> <vkey> [<vkey>...]
package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: noteverify <note-file|-> <vkey> [<vkey>...]")
		os.Exit(2)
	}
	var msg []byte
	var err error
	if os.Args[1] == "-" {
		msg, err = io.ReadAll(os.Stdin)
	} else {
		msg, err = os.ReadFile(os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	var verifiers []note.Verifier
	var skipped []string // "name+keyhash" of vkeys stock note cannot verify (our 0x04 cosigner key)
	for _, vk := range os.Args[2:] {
		v, err := note.NewVerifier(vk)
		if err != nil && err.Error() == "unknown verifier algorithm" {
			skipped = append(skipped, strings.Join(strings.SplitN(vk, "+", 3)[:2], "+"))
			continue
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad vkey %s: %v\n", vk, err)
			os.Exit(2)
		}
		verifiers = append(verifiers, v)
	}
	n, err := note.Open(msg, note.VerifierList(verifiers...))
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	for _, s := range n.Sigs {
		fmt.Printf("OK %s %08x\n", s.Name, s.Hash)
	}
	for _, s := range n.UnverifiedSigs { // present and from a supplied key, but NOT checked by this tool
		if slices.Contains(skipped, fmt.Sprintf("%s+%08x", s.Name, s.Hash)) {
			fmt.Printf("UNCHECKED %s %08x (stock sumdb/note cannot verify this signature type)\n", s.Name, s.Hash)
		}
	}
}
