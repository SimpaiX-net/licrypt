package tests

import (
	"crypto/hmac"
	"crypto/sha512"
	"testing"

	aesctr "github.com/SimpaiX-net/licrypt/aes-ctr"
)

func BenchmarkAES128CTRHMAC(b *testing.B) {
	crypt, err := (&aesctr.Crypter{}).Init(
		SECRET,
		hmac.New(sha512.New, SECRET),
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