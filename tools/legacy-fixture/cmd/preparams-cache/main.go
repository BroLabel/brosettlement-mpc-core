// TEST ONLY — NEVER FUND. Run only in this isolated, pinned v1.5.0 module.
package main

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"

	kg "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: preparams-cache input-public-preparams.json NEW-output.gob")
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		panic("missing build metadata")
	}
	found := false
	for _, dep := range info.Deps {
		if dep.Path == "github.com/bnb-chain/tss-lib" {
			if dep.Replace != nil || dep.Version != "v1.5.0" || dep.Sum != "h1:fuP69k0c4K9kaWCrG+FPH4GDdGZpMRhLyAaA+TyGn0w=" {
				panic("old producer dependency drift")
			}
			found = true
		}
	}
	if !found {
		panic("missing old TSS dependency")
	}
	input, err := os.ReadFile(os.Args[1])
	must(err)
	var params kg.LocalPreParams
	must(json.Unmarshal(input, &params))
	if !params.ValidateWithProof() {
		panic("incomplete public input")
	}
	file, err := os.OpenFile(os.Args[2], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(err)
	// This is exactly the old pool cache format: Gob of *LocalPreParams.
	must(gob.NewEncoder(file).Encode(&params))
	must(file.Close())
	fmt.Println("TEST ONLY — NEVER FUND: wrote old tss-lib v1.5.0 preparams Gob")
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
