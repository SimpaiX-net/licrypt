package aesctr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"hash"
	"sync"

	"github.com/SimpaiX-net/licrypt"
)

// The Crypter instance
type Crypter struct {
	hmac  hash.Hash
	block cipher.Block
	mx    sync.Mutex
}

func (c *Crypter) Init(key []byte, hmac hash.Hash) (*Crypter, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	return &Crypter{hmac, block, sync.Mutex{}}, nil
}

func (c *Crypter) Encrypt(input []byte) (licrypt.HexStr, error) {
	cipherText := make([]byte, c.hmac.Size()+c.block.BlockSize()+len(input))
	iv := cipherText[c.hmac.Size() : c.hmac.Size()+c.block.BlockSize()]

	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(c.block, iv)
	stream.XORKeyStream(cipherText[c.hmac.Size()+c.block.BlockSize():], input)

	// need mutex lock due to hmac's internal state cache
	// which we'll vw resetting below
	c.mx.Lock()
	defer c.mx.Unlock()

	// make sure it starts with a clean state
	c.hmac.Reset()

	if _, err := c.hmac.Write(cipherText[c.hmac.Size():]); err != nil {
		return nil, err
	}

	copy(cipherText[:c.hmac.Size()], c.hmac.Sum(nil))
	hexStr := make(licrypt.HexStr, hex.EncodedLen(len(cipherText)))

	hex.Encode(hexStr, cipherText)
	return hexStr, nil
}

func (c *Crypter) Decrypt(input licrypt.HexStr) ([]byte, error) {
	// hmac | iv | data
	decoded := make(licrypt.HexStr, hex.DecodedLen(len(input)))

	_, err := hex.Decode(decoded, input)
	if err != nil {
		return nil, err
	}

	// need mutex lock due to hmac's internal state
	// which we reset below
	c.mx.Lock()
	defer c.mx.Unlock()

	// make sure it starts with a clean state
	c.hmac.Reset()

	if _, err = c.hmac.Write(decoded[c.hmac.Size():]); err != nil {
		return nil, err
	}

	if !hmac.Equal(c.hmac.Sum(nil), decoded[:c.hmac.Size()]) {
		return nil, ErrAuthFailure
	}

	decrypted := make([]byte, len(decoded[c.hmac.Size()+c.block.BlockSize():]))

	stream := cipher.NewCTR(c.block, decoded[c.hmac.Size():c.hmac.Size()+c.block.BlockSize()])
	stream.XORKeyStream(decrypted, decoded[c.hmac.Size()+c.block.BlockSize():])

	return decrypted, nil
}
