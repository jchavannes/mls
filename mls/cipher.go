package mls

import (
	"bytes"
	"fmt"
	"github.com/cisco/go-mls"
	syntax "github.com/cisco/go-tls-syntax"
)

type CipherText struct {
	GroupId             []byte
	Epoch               uint32
	ContentType         uint8
	SenderDataNonce     []byte
	EncryptedSenderData []byte
	AuthenticatedData   []byte
	Ciphertext          []byte
}

func (c *CipherText) Decrypt(state *State) ([]byte, error) {
	if !bytes.Equal(c.GroupId, state.State.GroupID) {
		return nil, fmt.Errorf("error ciphertext group ID mismatch")
	}
	if c.Epoch != uint32(state.State.Epoch) {
		return nil, fmt.Errorf("error ciphertext epoch mismatch")
	}
	sdAAD := getSenderDataAAD(c.GroupId, c.Epoch, c.ContentType, c.SenderDataNonce)
	sdAead, err := state.State.CipherSuite.NewAEAD(state.State.Keys.SenderDataKey)
	if err != nil {
		return nil, fmt.Errorf("error getting sender state cipher AEAD; %w", err)
	}
	sd, err := sdAead.Open(nil, c.SenderDataNonce, c.EncryptedSenderData, sdAAD)
	if err != nil {
		return nil, fmt.Errorf("error opening sender data; %w", err)
	}
	var sender mls.LeafIndex
	var generation uint32
	var reuseGuard [4]byte
	stream := syntax.NewReadStream(sd)
	if _, err := stream.ReadAll(&sender, &generation, &reuseGuard); err != nil {
		return nil, fmt.Errorf("error reading sender data; %w", err)
	}
	keys, err := state.State.Keys.ApplicationKeys.Get(sender, generation)
	if err != nil {
		return nil, fmt.Errorf("error getting application keys; %w", err)
	}
	state.State.Keys.ApplicationKeys.Erase(sender, generation)
	aad := getContentAAD(c.GroupId, c.Epoch, c.ContentType, c.AuthenticatedData, c.SenderDataNonce, c.EncryptedSenderData)
	aead, err := state.State.CipherSuite.NewAEAD(keys.Key)
	if err != nil {
		return nil, fmt.Errorf("error getting state cipher AEAD; %w", err)
	}
	content, err := aead.Open(nil, applyGuard(keys.Nonce, reuseGuard), c.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("error opening content; %w", err)
	}
	stream = syntax.NewReadStream(content)
	var mlsContent mls.MLSPlaintextContent
	var signature mls.Signature
	if _, err := stream.Read(&mlsContent); err != nil {
		return nil, fmt.Errorf("error reading MLS content; %w", err)
	}
	if _, err := stream.Read(&signature); err != nil {
		return nil, fmt.Errorf("error reading signature; %w", err)
	}
	if _, err := syntax.Unmarshal(content, &mlsContent); err != nil {
		return nil, fmt.Errorf("error unmarshaling MLS content; %w", err)
	}
	plainText := &PlainText{
		State:             state,
		GroupId:           state.State.GroupID,
		Epoch:             uint64(state.State.Epoch),
		Sender:            uint32(sender),
		AuthenticatedData: c.AuthenticatedData,
		Content:           mlsContent,
		Signature:         signature,
	}
	keyPackage, ok := state.State.Tree.KeyPackage(sender)
	if !ok {
		return nil, fmt.Errorf("error getting key package for sender")
	}
	sigPubKey := keyPackage.Credential.PublicKey()
	toBeSigned, err := plainText.toBeSigned()
	if err != nil {
		return nil, fmt.Errorf("error getting plaintext to be signed; %w", err)
	}
	if !state.State.Scheme.Verify(sigPubKey, toBeSigned, signature.Data) {
		return nil, fmt.Errorf("error verifying signature")
	}
	return mlsContent.Application.Data, nil
}
