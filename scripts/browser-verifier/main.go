//go:build js && wasm

// The bridge exposes offline verification without providing network or file access.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"syscall/js"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type offlineLoader struct{}

func (offlineLoader) Load(string) (any, error) {
	return nil, errors.New("cannot load external schemas")
}

type browserRegexp struct {
	pattern string
	regex   js.Value
}

func (pattern browserRegexp) String() string {
	return pattern.pattern
}

func (pattern browserRegexp) MatchString(value string) bool {
	return pattern.regex.Call("test", value).Bool()
}

func compilePattern(pattern string) (compiled jsonschema.Regexp, err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("invalid JSON Schema pattern")
		}
	}()
	return browserRegexp{pattern, js.Global().Get("RegExp").New(pattern)}, nil
}

func checkSchema(_ js.Value, args []js.Value) (result any) {
	defer failClosed(&result)
	if len(args) != 2 {
		return false
	}
	// The exact published schema is embedded by the artifact builder and passed by the page.
	schema, err := jsonschema.UnmarshalJSON(bytes.NewBufferString(args[0].String()))
	if err != nil {
		return false
	}
	object, ok := schema.(map[string]any)
	if !ok {
		return false
	}
	resource, ok := object["$id"].(string)
	if !ok {
		return false
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(offlineLoader{})
	compiler.AssertFormat()
	// Patterns come only from the embedded, trusted schema and use ECMAScript syntax.
	compiler.UseRegexpEngine(compilePattern)
	if err = compiler.AddResource(resource, schema); err != nil {
		return false
	}
	compiled, err := compiler.Compile(resource)
	if err != nil {
		return false
	}
	manifest, err := jsonschema.UnmarshalJSON(bytes.NewBufferString(args[1].String()))
	return err == nil && compiled.Validate(manifest) == nil
}

func checkSigstore(_ js.Value, args []js.Value) (result any) {
	defer failClosed(&result)
	if len(args) != 5 || args[3].String() == "" || args[4].String() == "" {
		return false
	}
	if args[0].Length() < 1 || args[0].Length() > 1024*1024 {
		return false
	}
	artifact := make([]byte, args[0].Length())
	if js.CopyBytesToGo(artifact, args[0]) != len(artifact) {
		return false
	}
	var signed bundle.Bundle
	if err := json.Unmarshal([]byte(args[1].String()), &signed); err != nil {
		return false
	}
	if signed.Bundle.GetMessageSignature() == nil {
		return false
	}
	entries, err := signed.TlogEntries()
	if err != nil || len(entries) == 0 {
		return false
	}
	for _, entry := range entries {
		if !entry.HasInclusionProof() {
			return false
		}
	}
	trusted, err := root.NewTrustedRootFromJSON([]byte(args[2].String()))
	if err != nil {
		return false
	}
	verifier, err := verify.NewVerifier(trusted, verify.WithTransparencyLog(1),
		verify.WithSignedCertificateTimestamps(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return false
	}
	identity, err := verify.NewShortCertificateIdentity(args[4].String(), "", args[3].String(), "")
	if err != nil {
		return false
	}
	_, err = verifier.Verify(&signed, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(artifact)),
		verify.WithCertificateIdentity(identity)))
	return err == nil
}

func failClosed(result *any) {
	if recover() != nil {
		*result = false
	}
}

func main() {
	js.Global().Set("setryaCheckSchema", js.FuncOf(checkSchema))
	js.Global().Set("setryaCheckSigstore", js.FuncOf(checkSigstore))
	select {}
}
