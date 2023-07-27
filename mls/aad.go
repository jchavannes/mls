package mls

import (
	syntax "github.com/cisco/go-tls-syntax"
)

type senderDataAAD struct {
	GroupID         []byte `tls:"head=1"`
	Epoch           uint32
	SenderDataNonce []byte `tls:"head=1"`
}

func getSenderDataAAD(groupId []byte, epoch uint32, nonce []byte) []byte {
	stream := syntax.NewWriteStream()
	if err := stream.Write(senderDataAAD{
		GroupID:         groupId,
		Epoch:           epoch,
		SenderDataNonce: nonce,
	}); err != nil {
		return nil
	}
	return stream.Data()
}

type contentAAD struct {
	GroupID             []byte `tls:"head=1"`
	Epoch               uint32
	AuthenticatedData   []byte `tls:"head=4"`
	SenderDataNonce     []byte `tls:"head=1"`
	EncryptedSenderData []byte `tls:"head=1"`
}

func getContentAAD(groupId []byte, epoch uint32, authenticatedData []byte,
	nonce []byte, encSenderData []byte) []byte {
	stream := syntax.NewWriteStream()
	if err := stream.Write(contentAAD{
		GroupID:             groupId,
		Epoch:               epoch,
		AuthenticatedData:   authenticatedData,
		SenderDataNonce:     nonce,
		EncryptedSenderData: encSenderData,
	}); err != nil {
		return nil
	}
	return stream.Data()
}
