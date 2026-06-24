// Package jose provides the minimal JWT construction and parsing needed by
// go-oid4vci. It is internal to the module and not part of the public API.
//
// It uses only the standard library so the module has no mandatory
// dependencies.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Claims is a loose map of JWT claims. We use map[string]any rather than a
// concrete struct so that callers can include arbitrary registered and private
// claims without needing to extend the type.
type Claims map[string]any

// Header is a JWT JOSE header.
type Header map[string]any

// Signer can produce a raw signature over an arbitrary payload.
// This mirrors the interface defined in go-sd-jwt-vc and is reproduced here
// so that go-oid4vci has no dependency on the sibling module.
type Signer interface {
	Sign(payload []byte) ([]byte, error)
	Algorithm() string
	KeyID() string
}

// Sign produces a compact-serialised JWT with the given header additions and
// claims, signed by signer.
//
// The typ, alg, and kid header fields are set automatically; any additional
// headers in extraHeader override or supplement these.
func Sign(typ string, extraHeader Header, claims Claims, signer Signer) (string, error) {
	h := Header{
		"typ": typ,
		"alg": signer.Algorithm(),
	}
	if kid := signer.KeyID(); kid != "" {
		h["kid"] = kid
	}
	for k, v := range extraHeader {
		h[k] = v
	}

	hb, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("jose: marshalling header: %w", err)
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jose: marshalling claims: %w", err)
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(hb)
	payloadEnc := base64.RawURLEncoding.EncodeToString(pb)
	signingInput := headerEnc + "." + payloadEnc

	sig, err := signer.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("jose: signing: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Decode parses a compact-serialised JWT and returns its header and claims.
// It does NOT verify the signature.
func Decode(token string) (header Header, claims Claims, err error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("jose: not a three-part JWT")
	}

	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("jose: decoding header: %w", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("jose: decoding payload: %w", err)
	}

	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, fmt.Errorf("jose: parsing header: %w", err)
	}
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, nil, fmt.Errorf("jose: parsing claims: %w", err)
	}
	return header, claims, nil
}

// Verify checks the signature of a compact JWT using pub and alg.
// Supports ES256/384/512, RS256/384/512, PS256/384/512.
func Verify(token string, pub crypto.PublicKey, alg string) error {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("jose: malformed token")
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("jose: decoding signature: %w", err)
	}

	digest, h, err := digestFor(alg, signingInput)
	if err != nil {
		return err
	}

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return verifyEC(key, digest, sig)
	case *rsa.PublicKey:
		return verifyRSA(key, digest, sig, alg, h)
	default:
		return fmt.Errorf("jose: unsupported key type %T", pub)
	}
}

// BuildProofJWT constructs the key-proof JWT sent in a credential request.
// Defined in OID4VCI §7.2.1.1.
//
//   - issuerURI: the credential issuer's identifier (aud claim)
//   - clientID:  the wallet's client_id, or empty for public clients
//   - nonce:     the c_nonce from the token response
func BuildProofJWT(signer Signer, issuerURI, clientID, nonce string) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		"aud":   issuerURI,
		"iat":   now.Unix(),
		"nonce": nonce,
	}
	if clientID != "" {
		claims["iss"] = clientID
	}

	extra := Header{}
	// The proof JWT must carry the holder's public key in the header when
	// no kid is set (JWK thumbprint or embedded JWK). Callers that supply
	// a Signer with a KeyID satisfy the kid requirement automatically.

	return Sign("openid4vci-proof+jwt", extra, claims, signer)
}

// ValidateProofJWT parses and validates a proof JWT from a credential request.
// It checks the typ header, the aud claim, and the nonce. Signature
// verification is the caller's responsibility (they supply the public key from
// the JWT's own jwk header or kid lookup).
func ValidateProofJWT(token, expectedIssuer, expectedNonce string) (header Header, claims Claims, err error) {
	header, claims, err = Decode(token)
	if err != nil {
		return nil, nil, fmt.Errorf("jose: proof JWT decode: %w", err)
	}

	typ, _ := header["typ"].(string)
	if typ != "openid4vci-proof+jwt" {
		return nil, nil, fmt.Errorf("jose: proof JWT typ %q, want openid4vci-proof+jwt", typ)
	}

	aud, _ := claims["aud"].(string)
	if aud != expectedIssuer {
		return nil, nil, fmt.Errorf("jose: proof JWT aud %q, want %q", aud, expectedIssuer)
	}

	if expectedNonce != "" {
		nonce, _ := claims["nonce"].(string)
		// Accept an absent nonce: wallets following OID4VCI draft 14+ fetch
		// their nonce from a dedicated nonce_endpoint and may omit it here.
		// Only reject when the proof explicitly supplies a wrong nonce.
		if nonce != "" && nonce != expectedNonce {
			return nil, nil, fmt.Errorf("jose: proof JWT nonce mismatch")
		}
	}

	return header, claims, nil
}

// ThumbprintSHA256 computes the JWK SHA-256 thumbprint of pub as a
// base64url-encoded string. Useful as a stable key identifier.
func ThumbprintSHA256(pub crypto.PublicKey) (string, error) {
	m, err := publicKeyToJWK(pub)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// PublicKeyToJWKMap returns a JWK representation of pub as a map, suitable
// for embedding in a JWT header or cnf claim.
func PublicKeyToJWKMap(pub crypto.PublicKey) (map[string]any, error) {
	return publicKeyToJWK(pub)
}

// --- internal helpers ---

func digestFor(alg string, data []byte) ([]byte, crypto.Hash, error) {
	switch alg {
	case "ES256", "RS256", "PS256":
		s := sha256.Sum256(data)
		return s[:], crypto.SHA256, nil
	case "ES384", "RS384", "PS384":
		s := sha512.Sum384(data)
		return s[:], crypto.SHA384, nil
	case "ES512", "RS512", "PS512":
		s := sha512.Sum512(data)
		return s[:], crypto.SHA512, nil
	default:
		return nil, 0, fmt.Errorf("jose: unsupported algorithm %q", alg)
	}
}

func verifyEC(key *ecdsa.PublicKey, digest, sig []byte) error {
	l := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:l])
	s := new(big.Int).SetBytes(sig[l:])
	if !ecdsa.Verify(key, digest, r, s) {
		return fmt.Errorf("jose: ECDSA signature invalid")
	}
	return nil
}

func verifyRSA(key *rsa.PublicKey, digest, sig []byte, alg string, h crypto.Hash) error {
	if strings.HasPrefix(alg, "PS") {
		return rsa.VerifyPSS(key, h, digest, sig, nil)
	}
	return rsa.VerifyPKCS1v15(key, h, digest, sig)
}

func publicKeyToJWK(pub crypto.PublicKey) (map[string]any, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		xBytes := k.X.Bytes()
		yBytes := k.Y.Bytes()
		// Left-pad to the curve byte size.
		xPad := make([]byte, size)
		yPad := make([]byte, size)
		copy(xPad[size-len(xBytes):], xBytes)
		copy(yPad[size-len(yBytes):], yBytes)
		return map[string]any{
			"kty": "EC",
			"crv": k.Curve.Params().Name,
			"x":   base64.RawURLEncoding.EncodeToString(xPad),
			"y":   base64.RawURLEncoding.EncodeToString(yPad),
		}, nil
	case *rsa.PublicKey:
		eBytes := big.NewInt(int64(k.E)).Bytes()
		return map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(eBytes),
		}, nil
	default:
		return nil, fmt.Errorf("jose: unsupported key type %T", pub)
	}
}

// ECDSASigner is a convenience Signer backed by an *ecdsa.PrivateKey.
// Suitable for tests and simple deployments; production code should use
// a key management system.
type ECDSASigner struct {
	Key *ecdsa.PrivateKey
	KID string
	Alg string // defaults to ES256
}

func (s *ECDSASigner) Sign(payload []byte) ([]byte, error) {
	h, _, err := digestFor(s.Algorithm(), payload)
	if err != nil {
		return nil, err
	}
	r, sv, err := ecdsa.Sign(rand.Reader, s.Key, h)
	if err != nil {
		return nil, err
	}
	// Encode as fixed-length big-endian concatenation (JWS format).
	size := (s.Key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	rb := r.Bytes()
	sb := sv.Bytes()
	copy(sig[size-len(rb):size], rb)
	copy(sig[2*size-len(sb):], sb)
	return sig, nil
}

func (s *ECDSASigner) Algorithm() string {
	if s.Alg != "" {
		return s.Alg
	}
	switch s.Key.Curve.Params().Name {
	case "P-384":
		return "ES384"
	case "P-521":
		return "ES512"
	default:
		return "ES256"
	}
}

func (s *ECDSASigner) KeyID() string { return s.KID }
