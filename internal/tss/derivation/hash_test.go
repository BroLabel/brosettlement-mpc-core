package derivation

import (
	"bytes"
	"strings"
	"testing"
)

func TestHashV1UsesCanonicalPayloadAndDomain(t *testing.T) {
	ctx := Context{
		ProfileID:         "profile-1",
		ProfileTemplateID: "template-1",
		Chain:             "ethereum",
		Algorithm:         "ECDSA",
		Curve:             "SECP256K1",
		Scheme:            "bip32_public",
		PublicKeyFormat:   "UNCOMPRESSED_HEX",
		AccountPath:       "m/44h/60h/0h",
		ChildPath:         "/0/15",
		FullPath:          "m/44'/60'/0'/0/15",
		DescriptorVersion: 7,
		ProfileVersion:    3,
		KeyVersion:        2,
	}

	payload, err := CanonicalHashPayloadV1(ctx)
	if err != nil {
		t.Fatalf("CanonicalHashPayloadV1 returned error: %v", err)
	}
	wantPayload := `{"version":1,"profile_id":"profile-1","profile_template_id":"template-1","chain":"ethereum","algorithm":"ecdsa","curve":"secp256k1","scheme":"bip32_secp256k1","public_key_format":"uncompressed_hex","account_path":"m/44'/60'/0'","child_path":"/0/15","full_path":"m/44'/60'/0'/0/15","derived_public_key":"","descriptor_version":7,"profile_version":3,"key_version":2}`
	if string(payload) != wantPayload {
		t.Fatalf("payload mismatch\nwant: %s\n got: %s", wantPayload, payload)
	}

	got, err := HashV1(ctx)
	if err != nil {
		t.Fatalf("HashV1 returned error: %v", err)
	}
	want := "ffc977aefe65dfb06564cd6a5cd59d88056bebb63378fd63784af671f20f7f64"
	if got != want {
		t.Fatalf("hash mismatch: want %s got %s", want, got)
	}
}

func TestHashV1IgnoresAddressAndDescriptorFields(t *testing.T) {
	base := validECDSAContext()
	changed := base
	changed.AddressEncoding = "bech32"
	changed.ExpectedAddress = "chain-specific-address"
	changed.Descriptor = "descriptor payload"

	hashA, err := HashV1(base)
	if err != nil {
		t.Fatalf("HashV1 base error: %v", err)
	}
	hashB, err := HashV1(changed)
	if err != nil {
		t.Fatalf("HashV1 changed error: %v", err)
	}
	if hashA != hashB {
		t.Fatalf("expected ignored fields to keep hash stable: %s != %s", hashA, hashB)
	}
}

func TestHashV1PayloadDoesNotHTMLEscapeStrings(t *testing.T) {
	ctx := validECDSAContext()
	ctx.ProfileID = "profile<&>" + string(rune(0x2028)) + string(rune(0x2029)) + string([]byte{0xc3, 0xa9})

	payload, err := CanonicalHashPayloadV1(ctx)
	if err != nil {
		t.Fatalf("CanonicalHashPayloadV1 returned error: %v", err)
	}
	got := string(payload)
	if !strings.Contains(got, `"profile_id":"profile<&>`) {
		t.Fatalf("expected unescaped profile id in payload, got %s", got)
	}
	if strings.Contains(got, `\u003c`) || strings.Contains(got, `\u003e`) || strings.Contains(got, `\u0026`) || strings.Contains(got, `\u2028`) || strings.Contains(got, `\u2029`) || strings.Contains(got, `\u00e9`) {
		t.Fatalf("payload contains non-shortest escapes: %s", got)
	}
	if !bytes.Contains(payload, []byte{0xe2, 0x80, 0xa8}) || !bytes.Contains(payload, []byte{0xe2, 0x80, 0xa9}) || !bytes.Contains(payload, []byte{0xc3, 0xa9}) {
		t.Fatalf("payload does not contain raw UTF-8 non-ASCII bytes: %x", payload)
	}
}

func TestHashV1ChangesOnCommitmentAndVersionFields(t *testing.T) {
	base := validECDSAContext()
	baseHash, err := HashV1(base)
	if err != nil {
		t.Fatalf("HashV1 base error: %v", err)
	}

	cases := []Context{base, base, base, base, base, base, base}
	cases[0].DerivedPublicKey = validUncompressedSecp256k1Hex
	cases[1].ProfileVersion = 99
	cases[2].DescriptorVersion = 99
	cases[3].ChildPath = "/0/16"
	cases[3].FullPath = "m/44'/60'/0'/0/16"
	cases[4].ProfileTemplateID = "template-2"
	cases[5].PublicKeyFormat = "compressed_hex"
	cases[6].KeyVersion = 99

	for i, ctx := range cases {
		got, err := HashV1(ctx)
		if err != nil {
			t.Fatalf("HashV1 case %d error: %v", i, err)
		}
		if got == baseHash {
			t.Fatalf("case %d did not change hash", i)
		}
	}
}
