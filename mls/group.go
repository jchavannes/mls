package mls

import (
	"fmt"
)

type Group struct {
	Users  []*User
	States []*State
}

func NewGroup(user0 *User) (*Group, error) {
	state0, err := NewEmptyState(groupId, user0)
	if err != nil {
		return nil, fmt.Errorf("error creating empty state; %w", err)
	}
	return &Group{
		States: []*State{state0},
		Users:  []*User{user0},
	}, nil
}

func (g *Group) AddUser(user *User) error {
	state, err := g.States[0].AddUser(user)
	if err != nil {
		return fmt.Errorf("error adding user to state 0; %w", err)
	}
	g.States = append(g.States, state)
	g.Users = append(g.Users, user)
	return nil
}
