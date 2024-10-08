package main

import (
	"fmt"
	"github.com/jchavannes/mls/mls"
	"log"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("error running mls; %v", err)
	}

}

var (
	message = []byte("Hello, world!")
)

func run() error {
	user0, err := mls.GenUser()
	if err != nil {
		return fmt.Errorf("error generating user 0; %w", err)
	}
	group, err := mls.NewGroup(user0)
	if err != nil {
		return fmt.Errorf("error initializing group; %w", err)
	}
	user1, err := mls.GenUser()
	if err != nil {
		return fmt.Errorf("error generating user 1; %v", err)
	}
	if err := group.AddUser(user1); err != nil {
		return fmt.Errorf("error adding user 1; %w", err)
	}
	plainText := mls.NewPlainText(group.States[0], message)
	cipherText, err := plainText.Encrypt()
	if err != nil {
		return fmt.Errorf("error protecting message; %w", err)
	}
	unencrypted, err := cipherText.Decrypt(group.States[1])
	if err != nil {
		return fmt.Errorf("error unencrypting message; %w", err)
	}
	log.Printf("cipher (%d): %x, unencrypted: %x (%s)",
		len(cipherText.Ciphertext), cipherText.Ciphertext, unencrypted, unencrypted)
	return nil
}
