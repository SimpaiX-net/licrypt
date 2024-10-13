package licrypt

type HexStr = []byte

type Crypter interface {
	// Encrypt input and returns a hexstring
	Encrypt(input []byte) HexStr
	// Decrypts input and returns the decrypted input in plaintext
	Decrypt(input HexStr) (string, error)
}
