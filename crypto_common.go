package secure_hardware_extension

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/aead/cmac"
)

// EncryptAesCBC encrypts data using AES CBC
func EncryptAesCBC(key, data, iv []byte) ([]byte, error) {

	if len(iv) != 16 || len(key) != 16 {
		return nil, errors.New("invalid iv or key length")
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("invilad data length")
	}

	block, err := aes.NewCipher(key)
	if nil != err {
		return nil, err
	}

	cipherText := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, data)
	return cipherText, nil
}

// DecryptAesCBC decrypts data using AES CBC
func DecryptAesCBC(key, data, iv []byte) ([]byte, error) {

	if len(iv) != 16 || len(key) != 16 {
		return nil, errors.New("invalid iv or key length")
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("invilad data length")
	}

	block, err := aes.NewCipher(key)
	if nil != err {
		return nil, err
	}

	plainText := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plainText, data)
	return plainText, nil
}

// EncryptAesECB encrypts data using AES ECB
func EncryptAesECB(key, data []byte) ([]byte, error) {

	if len(key) != 16 || (len(data)%aes.BlockSize != 0) {
		return nil, errors.New("invalid key len or data size")
	}

	block, err := aes.NewCipher(key)
	if nil != err {
		return nil, err
	}

	cipherText := make([]byte, len(data))

	for start := 0; start < len(data); start += aes.BlockSize {
		block.Encrypt(cipherText[start:start+aes.BlockSize], data[start:start+aes.BlockSize])
	}
	return cipherText, nil
}

// DecryptAesECB decrypts data using AES ECB
func DecryptAesECB(key, data []byte) ([]byte, error) {

	if len(key) != 16 || (len(data)%aes.BlockSize != 0) {
		return nil, errors.New("invalid key len or data size")
	}

	block, err := aes.NewCipher(key)
	if nil != err {
		return nil, err
	}

	plainText := make([]byte, len(data))

	for start := 0; start < len(data); start += aes.BlockSize {
		block.Decrypt(plainText[start:start+aes.BlockSize], data[start:start+aes.BlockSize])
	}
	return plainText, nil
}

// CmacAES calculate block cmac value
func CmacAES(key, data []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if nil != err {
		return nil, err
	}

	cmac, err := cmac.Sum(data, block, aes.BlockSize)
	return cmac, err
}

// XorBytes performs XOR operation on two byte slices
func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	dst := make([]byte, n)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return dst
}

// MiyaguchiPreneel compresses input data using Miyaguchi-Preneel construction
func MiyaguchiPreneel(authKey, data []byte) ([]byte, error) {

	messages := make([][]byte, 2)
	messages[0] = authKey
	messages[1] = data

	key := make([]byte, 16)
	for _, message := range messages {
		// Encrypt the data in ECB mode
		encrypted, err := EncryptAesECB(key, message)
		if nil != err {
			return nil, err
		}
		key = xorBytes(key, encrypted)
		key = xorBytes(key, message)
	}
	return key, nil
}
