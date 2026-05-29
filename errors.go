// Package oid4vci implements OpenID for Verifiable Credential Issuance
// (OID4VCI, draft-ietf-oauth-credential-issuance).
//
// The package is split into three sub-packages by role:
//
//   - [issuer] implements the server-side protocol endpoints as an
//     [net/http.Handler], ready to mount into any Go HTTP server.
//   - [client] implements the wallet-side acquisition flow.
//   - [types] defines the shared protocol types.
//
// Neither the issuer nor the client sub-package has mandatory external
// dependencies beyond the standard library.
package oid4vci

import (
	"errors"
	"fmt"
)

// Protocol error codes defined by OID4VCI and OAuth 2.0.
const (
	ErrCodeInvalidRequest           = "invalid_request"
	ErrCodeInvalidToken             = "invalid_token"
	ErrCodeInvalidProof             = "invalid_proof"
	ErrCodeUnsupportedCredType      = "unsupported_credential_type"
	ErrCodeUnsupportedCredFormat    = "unsupported_credential_format"
	ErrCodeInvalidCredentialRequest = "invalid_credential_request"
	ErrCodeInvalidGrant             = "invalid_grant"
	ErrCodeAccessDenied             = "access_denied"
	ErrCodeServerError              = "server_error"
)

// Sentinel errors for the issuer and client sub-packages. Use [errors.Is] to
// test for these.
var (
	// ErrOfferNotFound is returned when a pre-authorised code cannot be
	// matched to a stored offer.
	ErrOfferNotFound = errors.New("oid4vci: offer not found")

	// ErrOfferExpired is returned when the pre-authorised code or offer has
	// passed its expiry time.
	ErrOfferExpired = errors.New("oid4vci: offer expired")

	// ErrOfferAlreadyUsed is returned when a one-time pre-authorised code
	// is presented a second time.
	ErrOfferAlreadyUsed = errors.New("oid4vci: offer already used")

	// ErrInvalidTxCode is returned when the supplied transaction code (PIN)
	// does not match the one stored with the offer.
	ErrInvalidTxCode = errors.New("oid4vci: invalid transaction code")

	// ErrInvalidAccessToken is returned when the access token presented to
	// the credential endpoint cannot be validated.
	ErrInvalidAccessToken = errors.New("oid4vci: invalid access token")

	// ErrInvalidProof is returned when the credential request's proof of
	// possession fails validation (bad signature, wrong nonce, etc.).
	ErrInvalidProof = errors.New("oid4vci: invalid proof")

	// ErrUnsupportedFormat is returned when the requested credential format
	// is not in the issuer's supported set.
	ErrUnsupportedFormat = errors.New("oid4vci: unsupported credential format")

	// ErrUnsupportedCredentialType is returned when the requested VCT or
	// configuration ID is not offered by this issuer.
	ErrUnsupportedCredentialType = errors.New("oid4vci: unsupported credential type")

	// ErrMetadataUnavailable is returned by the client when the issuer
	// metadata document cannot be fetched or parsed.
	ErrMetadataUnavailable = errors.New("oid4vci: metadata unavailable")

	// ErrNoCNonce is returned by the client when the token response does not
	// include a c_nonce but one is required to build a proof.
	ErrNoCNonce = errors.New("oid4vci: no c_nonce in token response")
)

// ProtocolError represents an OID4VCI/OAuth 2.0 error response received from
// the server. The client sub-package returns this when the server replies with
// an error JSON body.
type ProtocolError struct {
	// Code is the machine-readable error code (e.g. "invalid_proof").
	Code string
	// Description is the human-readable error_description field.
	Description string
	// CNonce is the fresh nonce returned on "invalid_proof" so the caller
	// can retry.
	CNonce string
}

func (e *ProtocolError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oid4vci: server error %q: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("oid4vci: server error %q", e.Code)
}

// IsInvalidProof reports whether err is a ProtocolError with code
// "invalid_proof". The client can use this to detect a stale c_nonce and
// retry with the fresh one in err.(*ProtocolError).CNonce.
func IsInvalidProof(err error) bool {
	var pe *ProtocolError
	return errors.As(err, &pe) && pe.Code == ErrCodeInvalidProof
}
