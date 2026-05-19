package derivation

import (
	"fmt"
	"strconv"
	"strings"
)

func normalizeECDSAContext(out Context) (Context, error) {
	if out.Curve != CurveSecp256k1 {
		return Context{}, fmt.Errorf("%w: ecdsa curve=%s", ErrUnsupportedAlgorithmCurve, out.Curve)
	}
	switch out.Scheme {
	case DerivationSchemeBIP32Public:
		out.Scheme = DerivationSchemeBIP32Secp256k1
	case DerivationSchemeBIP32Secp256k1:
	default:
		return Context{}, fmt.Errorf("%w: scheme=%s", ErrUnsupportedDerivationScheme, out.Scheme)
	}

	account, err := NormalizeAccountPath(out.AccountPath)
	if err != nil {
		return Context{}, err
	}
	child, _, err := NormalizeChildPath(out.ChildPath)
	if err != nil {
		return Context{}, err
	}
	full := CanonicalFullPath(account, child)
	if strings.TrimSpace(out.FullPath) != "" {
		got, err := NormalizeFullPath(out.FullPath)
		if err != nil {
			return Context{}, err
		}
		if got != full {
			return Context{}, fmt.Errorf("%w: full_path mismatch", ErrDerivationPathInvalid)
		}
	}
	if err := ValidateUncompressedSecp256k1Hex(out.DerivedPublicKey); err != nil {
		return Context{}, err
	}

	out.AccountPath = account
	out.ChildPath = child
	out.FullPath = full
	return out, nil
}

func normalizeEdDSAContext(out Context) (Context, error) {
	if out.Curve != CurveEd25519 {
		return Context{}, fmt.Errorf("%w: eddsa curve=%s", ErrUnsupportedAlgorithmCurve, out.Curve)
	}
	if out.Scheme != DerivationSchemeSLIP10Ed25519 {
		return Context{}, fmt.Errorf("%w: scheme=%s", ErrUnsupportedDerivationScheme, out.Scheme)
	}

	account, err := NormalizeAccountPath(out.AccountPath)
	if err != nil {
		return Context{}, err
	}
	child, _, err := NormalizeChildPath(out.ChildPath)
	if err != nil {
		return Context{}, err
	}
	full := CanonicalFullPath(account, child)
	if strings.TrimSpace(out.FullPath) != "" {
		got, err := NormalizeFullPath(out.FullPath)
		if err != nil {
			return Context{}, err
		}
		if got != full {
			return Context{}, fmt.Errorf("%w: full_path mismatch", ErrDerivationPathInvalid)
		}
	}

	out.AccountPath = account
	out.ChildPath = child
	out.FullPath = full
	return out, nil
}

func NormalizeAccountPath(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "m" || !strings.HasPrefix(s, "m/") {
		return "", fmt.Errorf("%w: account_path=%q", ErrInvalidDerivationContext, raw)
	}

	parts := strings.Split(strings.TrimPrefix(s, "m/"), "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized, err := normalizeAccountPathComponent(part)
		if err != nil {
			return "", err
		}
		out = append(out, normalized)
	}
	return "m/" + strings.Join(out, "/"), nil
}

func normalizeAccountPathComponent(part string) (string, error) {
	if part == "" || strings.ContainsAny(part, " +-") {
		return "", fmt.Errorf("%w: account_path segment=%q", ErrInvalidDerivationContext, part)
	}

	hardened := strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") || strings.HasSuffix(part, "H")
	core := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(part, "'"), "h"), "H")
	if core == "" || strings.ContainsAny(core, "'hH") {
		return "", fmt.Errorf("%w: account_path segment=%q", ErrInvalidDerivationContext, part)
	}
	n, err := strconv.ParseUint(core, 10, 32)
	if err != nil || n >= 0x80000000 {
		return "", fmt.Errorf("%w: account_path segment=%q", ErrInvalidDerivationContext, part)
	}
	if hardened {
		return strconv.FormatUint(n, 10) + "'", nil
	}
	return strconv.FormatUint(n, 10), nil
}

func NormalizeChildPath(raw string) (string, []uint32, error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "m/") || !strings.HasPrefix(s, "/") {
		return "", nil, fmt.Errorf("%w: child_path=%q", ErrDerivationPathInvalid, raw)
	}

	parts := strings.Split(strings.TrimPrefix(s, "/"), "/")
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("%w: child_path=%q", ErrDerivationPathInvalid, raw)
	}

	indices := make([]uint32, 0, 2)
	for _, part := range parts {
		if strings.ContainsAny(part, "'hH +-") {
			return "", nil, fmt.Errorf("%w: child_path=%q", ErrDerivationPathInvalid, raw)
		}
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return "", nil, fmt.Errorf("%w: child_path=%q", ErrDerivationPathInvalid, raw)
		}
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil || n >= 0x80000000 {
			return "", nil, fmt.Errorf("%w: child_path=%q", ErrDerivationPathInvalid, raw)
		}
		indices = append(indices, uint32(n))
	}

	return "/" + strconv.FormatUint(uint64(indices[0]), 10) + "/" + strconv.FormatUint(uint64(indices[1]), 10), indices, nil
}

func NormalizeFullPath(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || s != "m" && !strings.HasPrefix(s, "m/") {
		return "", fmt.Errorf("%w: full_path=%q", ErrDerivationPathInvalid, raw)
	}

	parts := strings.Split(strings.TrimPrefix(s, "m/"), "/")
	if len(parts) < 3 {
		return "", fmt.Errorf("%w: full_path=%q", ErrDerivationPathInvalid, raw)
	}

	accountParts := parts[:len(parts)-2]
	childParts := parts[len(parts)-2:]
	account, err := NormalizeAccountPath("m/" + strings.Join(accountParts, "/"))
	if err != nil {
		return "", err
	}
	child, _, err := NormalizeChildPath("/" + strings.Join(childParts, "/"))
	if err != nil {
		return "", err
	}
	return CanonicalFullPath(account, child), nil
}

func CanonicalFullPath(accountPath, childPath string) string {
	return strings.TrimRight(accountPath, "/") + childPath
}
