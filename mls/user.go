package mls

import (
	"fmt"
	"github.com/cisco/go-mls"
)

type User struct {
	Secret     []byte
	SigPriv    mls.SignaturePrivateKey
	Cred       mls.Credential
	KeyPackage mls.KeyPackage
}

func GenUser() (*User, error) {
	secret := randomBytes(32)
	sigPriv, err := scheme.Derive(secret)
	if err != nil {
		return nil, fmt.Errorf("error deriving signature key; %w", err)
	}
	cred := mls.NewBasicCredential(userId, scheme, sigPriv.PublicKey)
	keyPackage, err := mls.NewKeyPackageWithSecret(suite, secret, cred, sigPriv)
	if err != nil {
		return nil, fmt.Errorf("error creating key package; %w", err)
	}
	return &User{
		Secret:     secret,
		SigPriv:    sigPriv,
		Cred:       *cred,
		KeyPackage: *keyPackage,
	}, nil
}
