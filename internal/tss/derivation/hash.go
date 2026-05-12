package derivation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"unicode/utf8"
)

const hashDomainV1 = "brosettlement.derivation_context.v1"
const jsonHex = "0123456789abcdef"

func CanonicalHashPayloadV1(in Context) ([]byte, error) {
	ctx, err := NormalizeContext(in)
	if err != nil {
		return nil, err
	}

	fields := []struct {
		name  string
		value string
	}{
		{"profile_id", ctx.ProfileID},
		{"profile_template_id", ctx.ProfileTemplateID},
		{"chain", ctx.Chain},
		{"algorithm", ctx.Algorithm},
		{"curve", ctx.Curve},
		{"scheme", ctx.Scheme},
		{"public_key_format", ctx.PublicKeyFormat},
		{"account_path", ctx.AccountPath},
		{"child_path", ctx.ChildPath},
		{"full_path", ctx.FullPath},
		{"derived_public_key", ctx.DerivedPublicKey},
	}
	for _, field := range fields {
		if !utf8.ValidString(field.value) {
			return nil, fmt.Errorf("%w: %s is not valid utf-8", ErrInvalidDerivationContext, field.name)
		}
	}

	payload := make([]byte, 0, 256)
	payload = append(payload, `{"version":1`...)
	for _, field := range fields {
		payload = appendJSONStringField(payload, field.name, field.value)
	}
	payload = appendJSONUintField(payload, "descriptor_version", ctx.DescriptorVersion)
	payload = appendJSONUintField(payload, "profile_version", ctx.ProfileVersion)
	payload = appendJSONUintField(payload, "key_version", ctx.KeyVersion)
	payload = append(payload, '}')
	return payload, nil
}

func HashV1(in Context) (string, error) {
	payload, err := CanonicalHashPayloadV1(in)
	if err != nil {
		return "", err
	}

	input := append([]byte(hashDomainV1+"\n"), payload...)
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:]), nil
}

func appendJSONStringField(dst []byte, name, value string) []byte {
	dst = append(dst, `,"`...)
	dst = append(dst, name...)
	dst = append(dst, `":`...)
	return appendJSONString(dst, value)
}

func appendJSONUintField(dst []byte, name string, value uint32) []byte {
	dst = append(dst, `,"`...)
	dst = append(dst, name...)
	dst = append(dst, `":`...)
	return strconv.AppendUint(dst, uint64(value), 10)
}

func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); i++ {
		esc := ""
		switch s[i] {
		case '\\':
			esc = `\\`
		case '"':
			esc = `\"`
		case '\b':
			esc = `\b`
		case '\f':
			esc = `\f`
		case '\n':
			esc = `\n`
		case '\r':
			esc = `\r`
		case '\t':
			esc = `\t`
		default:
			if s[i] < 0x20 {
				dst = append(dst, s[start:i]...)
				dst = append(dst, `\u00`...)
				dst = append(dst, jsonHex[s[i]>>4], jsonHex[s[i]&0x0f])
				start = i + 1
			}
			continue
		}
		dst = append(dst, s[start:i]...)
		dst = append(dst, esc...)
		start = i + 1
	}
	dst = append(dst, s[start:]...)
	dst = append(dst, '"')
	return dst
}
