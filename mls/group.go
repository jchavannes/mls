package mls

import (
	"fmt"
	"github.com/cisco/go-mls"
)

type Group struct {
	Users  []*User
	States []*mls.State
}

func NewGroup(user0 *User) (*Group, error) {
	state0, err := mls.NewEmptyState(groupId, user0.Secret, user0.SigPriv, user0.KeyPackage)
	if err != nil {
		return nil, fmt.Errorf("error creating empty state; %w", err)
	}
	return &Group{
		States: []*mls.State{state0},
		Users:  []*User{user0},
	}, nil
}

func (g *Group) AddUser(user *User) error {
	add, err := g.States[0].Add(user.KeyPackage)
	if err != nil {
		return fmt.Errorf("error adding key package to initial state; %w", err)
	}
	if _, err := g.States[0].Handle(add); err != nil {
		return fmt.Errorf("error handling state add; %w", err)
	}
	commitSecret := randomBytes(32)
	_, welcome, next, err := g.States[0].Commit(commitSecret)
	if err != nil {
		return fmt.Errorf("error committing state; %w", err)
	}
	g.States[0] = next
	state, err := mls.NewJoinedState(user.Secret, []mls.SignaturePrivateKey{user.SigPriv},
		[]mls.KeyPackage{user.KeyPackage}, *welcome)
	if err != nil {
		return fmt.Errorf("error user joining state; %w", err)
	}
	g.States = append(g.States, state)
	g.Users = append(g.Users, user)
	return nil
}
