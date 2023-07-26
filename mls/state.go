package mls

import (
	"fmt"
	"github.com/cisco/go-mls"
)

type State struct {
	State *mls.State
}

func NewEmptyState(groupId []byte, user *User) (*State, error) {
	state, err := mls.NewEmptyState(groupId, user.Secret, user.SigPriv, user.KeyPackage)
	if err != nil {
		return nil, err
	}
	return &State{State: state}, nil
}

func (s *State) AddUser(user *User) (*State, error) {
	add, err := s.State.Add(user.KeyPackage)
	if err != nil {
		return nil, fmt.Errorf("error adding key package to initial state; %w", err)
	}
	if _, err := s.State.Handle(add); err != nil {
		return nil, fmt.Errorf("error handling state add; %w", err)
	}
	commitSecret := randomBytes(32)
	_, welcome, next, err := s.State.Commit(commitSecret)
	if err != nil {
		return nil, fmt.Errorf("error committing state; %w", err)
	}
	s.State = next
	state, err := mls.NewJoinedState(user.Secret, []mls.SignaturePrivateKey{user.SigPriv},
		[]mls.KeyPackage{user.KeyPackage}, *welcome)
	if err != nil {
		return nil, fmt.Errorf("error user joining state; %w", err)
	}
	return &State{State: state}, nil
}

func (s *State) Encrypt(message []byte) (*CipherText, error) {
	cipherText, err := s.State.Protect(message)
	if err != nil {
		return nil, fmt.Errorf("error protecting message; %w", err)
	}
	return &CipherText{CipherText: cipherText}, nil
}

func (s *State) Decrypt(cipherText *CipherText) ([]byte, error) {
	message, err := s.State.Unprotect(cipherText.CipherText)
	if err != nil {
		return nil, fmt.Errorf("error unprotecting ciphertext; %w", err)
	}
	return message, nil
}
