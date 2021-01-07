package aes

import (
	"crypto/cipher"
	"github.com/CloudmindsRobot/gmgo/crypto/internal/sm4"
)

const SM4BlockSize = sm4.BlockSize

func SM4NewCipher(key []byte) (cipher.Block, error) {
	return sm4.NewCipher(key)
}
