package tests

import (
	"testing"

	aesgcm "github.com/SimpaiX-net/licrypt/aes-gcm"
)

func BenchmarkAES128GCM(b *testing.B) {
	crypt, err := (&aesgcm.Crypter{}).Init(
		SECRET,
	)

	if err != nil {
		b.Fatal(err)
	}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			encr, _ := crypt.Encrypt([]byte("hallo wereld"))
			crypt.Decrypt(encr)
		}
	})
}