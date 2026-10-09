package otp

import (
	"bytes"
	"errors"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

// sm3Hash 计算 SM3 哈希，返回 32 字节。
func sm3Hash(data []byte) []byte {
	sum := sm3.Sum(data)
	return sum[:]
}

// hmacSM3 实现标准 HMAC-SM3(key, data) → 32 字节，
// 与 Python 参考实现（gmssl）的 hmac_sm3 逐字节一致。
func hmacSM3(key, data []byte) []byte {
	if len(key) > 64 {
		key = sm3Hash(key)
	}
	if len(key) < 64 {
		key = append(key, make([]byte, 64-len(key))...)
	}
	ipad := make([]byte, 64)
	opad := make([]byte, 64)
	for i, k := range key {
		ipad[i] = k ^ 0x36
		opad[i] = k ^ 0x5c
	}
	inner := sm3Hash(append(ipad, data...))
	return sm3Hash(append(opad, inner...))
}

// sm4ECBDecrypt SM4-ECB 解密 + PKCS7 去填充。
func sm4ECBDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(ciphertext) == 0 || len(ciphertext)%bs != 0 {
		return nil, errors.New("sm4: ciphertext length is not a multiple of block size")
	}
	out := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += bs {
		block.Decrypt(out[i:i+bs], ciphertext[i:i+bs])
	}
	return pkcs7Unpad(out)
}

// sm4ECBEncrypt SM4-ECB 加密 + PKCS7 填充。
func sm4ECBEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += block.BlockSize() {
		block.Encrypt(out[i:i+block.BlockSize()], padded[i:i+block.BlockSize()])
	}
	return out, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("sm4: cannot unpad empty data")
	}
	n := int(data[len(data)-1])
	if n == 0 || n > 16 || n > len(data) {
		return nil, errors.New("sm4: invalid PKCS7 padding")
	}
	if !bytes.Equal(data[len(data)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		return nil, errors.New("sm4: invalid PKCS7 padding")
	}
	return data[:len(data)-n], nil
}
