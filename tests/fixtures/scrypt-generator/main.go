// This test-only generator fixes logN=19 before encrypting synthetic bytes.
// It is not a general recovery exporter or passphrase-input interface.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "age test fixture generation failed")
		os.Exit(1)
	}
}

func main() {
	secret, err := io.ReadAll(os.NewFile(3, "fixture-passphrase"))
	fail(err)
	secret = bytes.TrimSuffix(secret, []byte("\n"))
	if len(secret) == 0 {
		fail(fmt.Errorf("empty passphrase"))
	}
	recipient, err := age.NewScryptRecipient(string(secret))
	fail(err)
	recipient.SetWorkFactor(19)
	writer, err := age.Encrypt(os.Stdout, recipient)
	fail(err)
	_, err = io.Copy(writer, os.Stdin)
	fail(err)
	fail(writer.Close())
}
