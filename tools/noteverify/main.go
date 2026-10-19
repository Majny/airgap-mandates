// noteverify verifies a signed note (C2SP signed-note / tlog-checkpoint) using ONLY the unmodified
// golang.org/x/mod/sumdb/note package. Usage: noteverify <note-file|-> <vkey> [<vkey>...]
package main

import (
	"fmt"
	"io"
	"os"

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
	for _, vk := range os.Args[2:] {
		v, err := note.NewVerifier(vk)
		if err != nil { // e.g. the 0x04 cosigner vkey: stock note only knows Ed25519 (0x01)
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", vk, err)
			continue
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
}
