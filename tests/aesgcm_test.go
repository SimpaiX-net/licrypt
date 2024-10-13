package tests

import (
	"testing"

	aesgcm "github.com/SimpaiX-net/licrypt/aes-gcm"
)

func TestAES128GCM_Crypter(t *testing.T) {
	crypt, err := (&aesgcm.Crypter{}).Init(
		SECRET,
	)

	if err != nil {
		t.Fatal(err)
	}

	encr, err := crypt.Encrypt([]byte("hallo wereld"))
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Encrypted: %s\n", encr)

	decr, err := crypt.Decrypt(encr)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Decrypted: %s", decr)
}
