package mls

import (
	"fmt"
	"github.com/cisco/go-mls"
	syntax "github.com/cisco/go-tls-syntax"
)

type PlainText struct {
	State     *State
	PlainText *mls.MLSPlaintext
}

func NewPlainText(state *State, message []byte) *PlainText {
	return &PlainText{
		State: state,
		PlainText: &mls.MLSPlaintext{
			GroupID: state.State.GroupID,
			Epoch:   state.State.Epoch,
			Sender: mls.Sender{
				Type:   mls.SenderTypeMember,
				Sender: uint32(state.State.Index),
			},
			Content: mls.MLSPlaintextContent{
				Application: &mls.ApplicationData{
					Data: message,
				},
			},
		},
	}
}

func (p *PlainText) Encrypt() (*CipherText, error) {
	if err := p.sign(); err != nil {
		return nil, fmt.Errorf("error signing plaintext; %w", err)
	}
	generation, keys := p.State.State.Keys.ApplicationKeys.Next(p.State.State.Index)
	var reuseGuard [4]byte
	copy(reuseGuard[:], randomBytes(4))
	stream := syntax.NewWriteStream()
	if err := stream.WriteAll(p.State.State.Index, generation, reuseGuard); err != nil {
		return nil, fmt.Errorf("error writing stream; %w", err)
	}
	senderData := stream.Data()
	senderDataNonce := make([]byte, p.State.State.CipherSuite.Constants().NonceSize)
	copy(senderDataNonce, randomBytes(len(senderDataNonce)))
	senderDataAADVal := getSenderDataAAD(p.State.State.GroupID, p.State.State.Epoch, mls.ContentTypeApplication, senderDataNonce)
	sdAead, _ := p.State.State.CipherSuite.NewAEAD(p.State.State.Keys.SenderDataKey)
	senderDataEncrypted := sdAead.Seal(nil, senderDataNonce, senderData, senderDataAADVal)
	stream2 := syntax.NewWriteStream()
	if err := stream2.Write(p.PlainText.Content); err != nil {
		return nil, fmt.Errorf("error writing plaintext to stream; %w", err)
	}
	if err := stream2.Write(p.PlainText.Signature); err != nil {
		return nil, fmt.Errorf("error writing signature to stream; %w", err)
	}
	content := stream2.Data()
	aad := getContentAAD(p.State.State.GroupID, p.State.State.Epoch, mls.ContentTypeApplication, p.PlainText.AuthenticatedData, senderDataNonce, senderDataEncrypted)
	aead, _ := p.State.State.CipherSuite.NewAEAD(keys.Key)
	contentCt := aead.Seal(nil, applyGuard(keys.Nonce, reuseGuard), content, aad)
	cipherText := &mls.MLSCiphertext{
		GroupID:             p.State.State.GroupID,
		Epoch:               p.State.State.Epoch,
		ContentType:         mls.ContentTypeApplication,
		AuthenticatedData:   p.PlainText.AuthenticatedData,
		SenderDataNonce:     senderDataNonce,
		EncryptedSenderData: senderDataEncrypted,
		Ciphertext:          contentCt,
	}
	return &CipherText{CipherText: cipherText}, nil
}

type plainTextToSign struct {
	GroupID           []byte `tls:"head=1"`
	Epoch             mls.Epoch
	Sender            mls.Sender
	AuthenticatedData []byte `tls:"head=4"`
	Content           mls.MLSPlaintextContent
}

func (p *PlainText) toBeSigned() ([]byte, error) {
	groupContext := p.State.GetContext()
	stream := syntax.NewWriteStream()
	if err := stream.Write(groupContext); err != nil {
		return nil, fmt.Errorf("error writing group context; %w", err)
	}
	if err := stream.Write(plainTextToSign{
		GroupID:           p.PlainText.GroupID,
		Epoch:             p.PlainText.Epoch,
		Sender:            p.PlainText.Sender,
		AuthenticatedData: p.PlainText.AuthenticatedData,
		Content:           p.PlainText.Content,
	}); err != nil {
		return nil, fmt.Errorf("error writing plaintext to sign; %w", err)
	}
	return stream.Data(), nil
}

func (p *PlainText) sign() error {
	toBeSigned, err := p.toBeSigned()
	if err != nil {
		return fmt.Errorf("error getting plaintext to sign; %w", err)
	}
	sig, err := p.State.State.Scheme.Sign(&p.State.State.IdentityPriv, toBeSigned)
	if err != nil {
		return fmt.Errorf("error signing plaintext; %w", err)
	}
	p.PlainText.Signature = mls.Signature{Data: sig}
	return nil
}
