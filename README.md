# go-oid4vci

[![Go Reference](https://pkg.go.dev/badge/github.com/alanh-pyxical/go-oid4vci.svg)](https://pkg.go.dev/github.com/alanh-pyxical/go-oid4vci)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An idiomatic Go implementation of [OpenID for Verifiable Credential Issuance (OID4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), focusing on the pre-authorised code flow.

## Overview

OID4VCI defines how a wallet acquires verifiable credentials from an issuer. This library implements both sides:

| Sub-package | Role | Responsibility |
|---|---|---|
| `issuer` | Server | Serves the credential, token, and metadata endpoints as an `http.Handler` |
| `client` | Wallet | Runs the acquisition flow — discover, token exchange, credential request |
| `types` | Shared | Protocol types (no logic) |

## Installation

```sh
go get github.com/alanh-pyxical/go-oid4vci
```

No mandatory external dependencies — core and client packages use only the standard library.

## Issuer (Server Side)

The issuer implements the pre-authorised code flow. Mount it into your HTTP server:

```go
import (
    "github.com/alanh-pyxical/go-oid4vci/issuer"
    "github.com/alanh-pyxical/go-oid4vci/types"
)

// 1. Define your credential configurations.
meta := types.IssuerMetadata{
    Issuer:             "https://bank.example",
    CredentialEndpoint: "https://bank.example/credential",
    TokenEndpoint:      "https://bank.example/token",
    CredentialConfigurationsSupported: map[string]types.CredentialConfiguration{
        "MortgageOffer": {
            Format: types.FormatSDJWTVC,
            VCT:    "https://schema.example/MortgageOffer",
        },
    },
}

// 2. Implement CredentialFactory to produce the actual credential.
//    Wire in go-sd-jwt-vc here.
factory := issuer.CredentialFactoryFunc(func(ctx context.Context, req *issuer.CredentialRequest) (string, string, error) {
    credential, err := mySDJWTIssuer.Issue(ctx, sdjwt.IssueRequest{
        VCT:       "https://schema.example/MortgageOffer",
        Subject:   req.SubjectID,
        HolderKey: req.HolderPublicKey,
        Claims:    req.Metadata,
    })
    return credential.String(), types.FormatSDJWTVC, err
})

// 3. Create the issuer with in-memory stores (swap for DB-backed in production).
i, err := issuer.New(meta,
    issuer.NewMemoryOfferStore(),
    issuer.NewMemoryTokenStore(),
    factory,
    issuer.RequireProof(), // recommended for production
)

// 4. Mount the handler.
mux.Handle("/", i.Handler())

// 5. Create offers when a customer is approved.
offerResp, err := i.NewOffer(ctx, issuer.OfferConfig{
    SubjectID:                  "customer-123",
    CredentialConfigurationIDs: []string{"MortgageOffer"},
    Metadata: map[string]any{
        "max_amount": 450000,
        "currency":   "GBP",
    },
})
// Deliver offerResp.OfferURI to the customer via QR, deep link, or email.
```

### Implementing `OfferStore` and `TokenStore`

The library ships with `MemoryOfferStore` and `MemoryTokenStore` for tests. For production, implement the interfaces against your database:

```go
type OfferStore interface {
    Save(ctx context.Context, offer *Offer) error
    Consume(ctx context.Context, preAuthCode string) (*Offer, error)
}

type TokenStore interface {
    Save(ctx context.Context, record *AccessTokenRecord) error
    Get(ctx context.Context, token string) (*AccessTokenRecord, error)
    RotateCNonce(ctx context.Context, token, newNonce string, expiresAt time.Time) (*AccessTokenRecord, error)
}
```

## Client (Wallet Side)

```go
import "github.com/alanh-pyxical/go-oid4vci/client"

c := client.New()

// One-shot: runs the full pre-auth flow.
credential, format, err := c.Acquire(ctx, offerURI, txCode, walletSigner)

// Or step-by-step, for wallets that need to persist state between steps:
session, err := c.ParseOffer(ctx, offerURI)
session, err  = c.RedeemOffer(ctx, session, txCode)
cred, fmt, session, err := c.RequestCredential(ctx, session, configID, walletSigner)
```

The `AcquisitionSession` is a plain struct — serialise it however you like to survive process restarts or present a PIN entry screen between steps.

### Implementing `Signer`

```go
type Signer interface {
    Sign(payload []byte) ([]byte, error)
    Algorithm() string
    KeyID() string
}
```

If your signer also implements `PublicKeyJWK() (map[string]any, error)`, the client automatically embeds your public key in the proof JWT header, enabling key binding. This is the same interface as `go-sd-jwt-vc`'s Signer, so one implementation satisfies both.

## Protocol Support

| Feature | Status |
|---|---|
| Pre-authorised code flow | ✅ |
| Transaction code (PIN) | ✅ |
| Proof of key possession (JWT proof) | ✅ |
| Batch credential endpoint | Planned |
| Authorisation code flow | Planned |
| Deferred credential issuance | Planned |
| Notification endpoint | Planned |

## Related Libraries

- [`go-sd-jwt-vc`](https://github.com/alanh-pyxical/go-sd-jwt-vc) — SD-JWT-VC issuance and verification
- [`go-oid4vp`](https://github.com/alanh-pyxical/go-oid4vp) — OpenID for Verifiable Presentations

## License

MIT — see [LICENSE](LICENSE).
