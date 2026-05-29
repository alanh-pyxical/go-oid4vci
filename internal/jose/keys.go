package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// PublicKeyToGoKey converts a JWK map (as decoded from JSON) into a Go
// crypto.PublicKey — either *ecdsa.PublicKey or *rsa.PublicKey.
// This is exposed for use by the issuer when extracting the holder key from
// a proof JWT header.
func PublicKeyToGoKey(m map[string]any) (any, error) {
	kty, _ := m["kty"].(string)
	switch kty {
	case "EC":
		return ecFromMap(m)
	case "RSA":
		return rsaFromMap(m)
	default:
		return nil, fmt.Errorf("jose: unsupported JWK kty %q", kty)
	}
}

func ecFromMap(m map[string]any) (*ecdsa.PublicKey, error) {
	crv, _ := m["crv"].(string)
	xStr, _ := m["x"].(string)
	yStr, _ := m["y"].(string)

	xb, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("jose: EC JWK x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("jose: EC JWK y: %w", err)
	}

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("jose: unsupported EC curve %q", crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}

func rsaFromMap(m map[string]any) (*rsa.PublicKey, error) {
	nStr, _ := m["n"].(string)
	eStr, _ := m["e"].(string)

	nb, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("jose: RSA JWK n: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("jose: RSA JWK e: %w", err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: int(new(big.Int).SetBytes(eb).Int64()),
	}, nil
}
