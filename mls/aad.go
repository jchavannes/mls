package mls

import (
	"github.com/cisco/go-mls"
	syntax "github.com/cisco/go-tls-syntax"
)

type senderDataAAD struct {
	GroupID         []byte `tls:"head=1"`
	Epoch           mls.Epoch
	ContentType     mls.ContentType
	SenderDataNonce []byte `tls:"head=1"`
}

func getSenderDataAAD(groupId []byte, epoch mls.Epoch, contentType mls.ContentType, nonce []byte) []byte {
	stream := syntax.NewWriteStream()
	if err := stream.Write(senderDataAAD{
		GroupID:         groupId,
		Epoch:           epoch,
		ContentType:     contentType,
		SenderDataNonce: nonce,
	}); err != nil {
		return nil
	}
	return stream.Data()
}

type contentAAD struct {
	GroupID             []byte `tls:"head=1"`
	Epoch               mls.Epoch
	ContentType         mls.ContentType
	AuthenticatedData   []byte `tls:"head=4"`
	SenderDataNonce     []byte `tls:"head=1"`
	EncryptedSenderData []byte `tls:"head=1"`
}

func getContentAAD(groupId []byte, epoch mls.Epoch, contentType mls.ContentType, authenticatedData []byte,
	nonce []byte, encSenderData []byte) []byte {
	stream := syntax.NewWriteStream()
	if err := stream.Write(contentAAD{
		GroupID:             groupId,
		Epoch:               epoch,
		ContentType:         contentType,
		AuthenticatedData:   authenticatedData,
		SenderDataNonce:     nonce,
		EncryptedSenderData: encSenderData,
	}); err != nil {
		return nil
	}
	return stream.Data()
}
