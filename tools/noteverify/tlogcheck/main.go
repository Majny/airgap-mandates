// tlogcheck prints golang.org/x/mod/sumdb/tlog (unmodified) tree hashes and proofs for the hex leaf hashes on stdin
// (one per line) as JSON, so tests can cross-check executor/audit/merkle.py against independent code.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/mod/sumdb/tlog"
)

func hexes(hs []tlog.Hash) []string {
	out := []string{}
	for _, h := range hs {
		out = append(out, hex.EncodeToString(h[:]))
	}
	return out
}

func main() {
	var stored []tlog.Hash
	r := tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(idx))
		for i, j := range idx {
			out[i] = stored[j]
		}
		return out, nil
	})
	sc := bufio.NewScanner(os.Stdin)
	var n int64
	for sc.Scan() {
		var h tlog.Hash
		if b, err := hex.DecodeString(sc.Text()); err != nil || len(b) != len(h) {
			fmt.Fprintln(os.Stderr, "bad leaf hash:", sc.Text())
			os.Exit(1)
		} else {
			copy(h[:], b)
		}
		add, err := tlog.StoredHashesForRecordHash(n, h, r)
		must(err)
		stored = append(stored, add...)
		n++
	}
	res := map[string]any{"roots": map[int64]string{}, "inclusion": map[string][]string{}, "consistency": map[string][]string{}}
	for size := int64(1); size <= n; size++ {
		th, err := tlog.TreeHash(size, r)
		must(err)
		res["roots"].(map[int64]string)[size] = hex.EncodeToString(th[:])
		for i := int64(0); i < size; i++ {
			p, err := tlog.ProveRecord(size, i, r)
			must(err)
			res["inclusion"].(map[string][]string)[fmt.Sprintf("%d/%d", i, size)] = hexes(p)
			if i > 0 {
				q, err := tlog.ProveTree(size, i, r)
				must(err)
				res["consistency"].(map[string][]string)[fmt.Sprintf("%d/%d", i, size)] = hexes(q)
			}
		}
	}
	must(json.NewEncoder(os.Stdout).Encode(res))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
