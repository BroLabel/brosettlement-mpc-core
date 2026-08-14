package tss

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
)

func TestShareCapabilitiesExposeOnlyTheirOwnOperations(t *testing.T) {
	readerType := reflect.TypeOf((*ShareReader)(nil)).Elem()
	writerType := reflect.TypeOf((*ShareWriter)(nil)).Elem()

	assertExactlyOneMethod(t, readerType, "LoadShare")
	assertExactlyOneMethod(t, writerType, "SaveShare")
	if _, ok := readerType.MethodByName("SaveShare"); ok {
		t.Fatal("share reader must not be able to mutate shares")
	}
	if _, ok := writerType.MethodByName("LoadShare"); ok {
		t.Fatal("share writer must not be able to load shares")
	}
}

func TestSaveShareInputContainsOnlyGenericPersistenceContext(t *testing.T) {
	inputType := reflect.TypeOf(SaveShareInput{})
	want := []struct {
		name string
		typ  reflect.Type
	}{
		{name: "SessionID", typ: reflect.TypeOf("")},
		{name: "KeyID", typ: reflect.TypeOf("")},
		{name: "LocalPartyID", typ: reflect.TypeOf("")},
		{name: "OpaqueDescriptorFingerprint", typ: reflect.TypeOf([]byte{})},
		{name: "CodecBlob", typ: reflect.TypeOf([]byte{})},
	}
	if inputType.NumField() != len(want) {
		t.Fatalf("SaveShareInput has %d fields, want %d", inputType.NumField(), len(want))
	}
	for index, expected := range want {
		field := inputType.Field(index)
		if field.Name != expected.name || field.Type != expected.typ {
			t.Fatalf("field %d = %s %s, want %s %s", index, field.Name, field.Type, expected.name, expected.typ)
		}
	}
}

func TestMetadataMismatchSentinelAliasesCoreError(t *testing.T) {
	if ErrMetadataMismatch != coreshares.ErrMetadataMismatch {
		t.Fatal("ErrMetadataMismatch does not preserve core error identity")
	}
	wrapped := fmt.Errorf("descriptor binding failed: %w", coreshares.ErrMetadataMismatch)
	if !errors.Is(wrapped, ErrMetadataMismatch) {
		t.Fatal("ErrMetadataMismatch does not match a wrapped core binding error")
	}
}

func assertExactlyOneMethod(t *testing.T, typ reflect.Type, name string) {
	t.Helper()
	if typ.NumMethod() != 1 {
		t.Fatalf("%s has %d methods, want 1", typ, typ.NumMethod())
	}
	if _, ok := typ.MethodByName(name); !ok {
		t.Fatalf("%s does not expose %s", typ, name)
	}
}

var _ interface {
	LoadShare(context.Context, string) (*StoredShare, error)
} = (ShareReader)(nil)

var _ interface {
	SaveShare(context.Context, SaveShareInput) error
} = (ShareWriter)(nil)
