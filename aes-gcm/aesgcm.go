package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/SimpaiX-net/licrypt"
)

// The Crypter instance
type Crypter struct {
	block cipher.Block
	mx    sync.Mutex
}

func (c *Crypter) Init(key []byte) (*Crypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &Crypter{block, sync.Mutex{}}, nil
}

func (c *Crypter) Encrypt(input []byte) (licrypt.HexStr, error) {
	nonce := make([]byte, 12)

	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c.block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, ErrNonceSizeToSmall
	}

	// input = <nonce | cipher>
	input = gcm.Seal(nonce, nonce, input, nil)

	hexStr := make(licrypt.HexStr, hex.EncodedLen(len(input)))
	hex.Encode(hexStr, input)

	return hexStr, nil
}

func (c *Crypter) Decrypt(input licrypt.HexStr) ([]byte, error) {
	decoded := make(licrypt.HexStr, hex.DecodedLen(len(input)))

	_, err := hex.Decode(decoded, input)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c.block)
	if err != nil {
		return nil, err
	}

	decrypted, err := gcm.Open(nil, decoded[:gcm.NonceSize()], decoded[gcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
