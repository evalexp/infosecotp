// Package otp 提供离线 OTP（国密 GUOMI-TOTP）计算能力：
// 解析二维码（sn|username|randomNumber|userSeed）→ 派生 SM4 密钥
// （HMAC-SM3）→ 解密 userSeed（SM4-ECB）→ 计算 OTP 种子（SM3）→ 生成动态口令。
package otp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result 离线 OTP 计算的完整结果（含中间值，便于排查）。
type Result struct {
	SN          string
	Username    string
	RandomNum   string
	UserSeedB64 string
	SM4KeyHex   string
	Part1       string
	Part2       string
	SeedHex     string
	Counter     int64
	OTP         string
	NextOTP     string
}

// Forge 离线 OTP 计算器。
type Forge struct {
	// LocalKey 本地密钥（解码后的字节）。
	LocalKey []byte
}

// New 使用内置本地密钥创建计算器。
func New() *Forge {
	return &Forge{LocalKey: DefaultLocalKey()}
}

// NewWithKey 使用自定义本地密钥（Base64）创建计算器。
func NewWithKey(keyB64 string) (*Forge, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid local key: %w", err)
	}
	return &Forge{LocalKey: key}, nil
}

// ParseQRContent 解析二维码内容 "sn|username|randomNumber|userSeed"。
func ParseQRContent(content string) (sn, username, randomNum, userSeedB64 string, err error) {
	parts := strings.Split(strings.TrimSpace(content), "|")
	if len(parts) < 4 {
		return "", "", "", "", fmt.Errorf("qr content format error: need 4 fields, got %d", len(parts))
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), strings.TrimSpace(parts[3]), nil
}

// ForgeFromQR 从二维码原始文本计算 OTP。tsMs 为时间戳（毫秒）。
func (f *Forge) ForgeFromQR(qrContent string, tsMs int64) (*Result, error) {
	sn, username, rand, seed, err := ParseQRContent(qrContent)
	if err != nil {
		return nil, err
	}
	return f.forge(sn, username, rand, seed, tsMs)
}

// ForgeFromImage 从二维码图片解析并计算 OTP。
func (f *Forge) ForgeFromImage(path string, tsMs int64) (*Result, error) {
	content, err := ParseQRCodeFromFile(path)
	if err != nil {
		return nil, err
	}
	return f.ForgeFromQR(content, tsMs)
}

// ForgeFromParts 直接使用已知字段计算 OTP（跳过二维码解析）。
func (f *Forge) ForgeFromParts(sn, username, randomNum, userSeedB64 string, tsMs int64) (*Result, error) {
	return f.forge(sn, username, randomNum, userSeedB64, tsMs)
}

var defaultForge = New()

// ForgeFromQR 便捷入口（使用内置本地密钥）。
func ForgeFromQR(qrContent string, tsMs int64) (*Result, error) {
	return defaultForge.ForgeFromQR(qrContent, tsMs)
}

// ForgeFromImage 便捷入口（使用内置本地密钥）。
func ForgeFromImage(path string, tsMs int64) (*Result, error) {
	return defaultForge.ForgeFromImage(path, tsMs)
}

// ForgeFromParts 便捷入口（使用内置本地密钥）。
func ForgeFromParts(sn, username, randomNum, userSeedB64 string, tsMs int64) (*Result, error) {
	return defaultForge.ForgeFromParts(sn, username, randomNum, userSeedB64, tsMs)
}

// forge 核心流程：派生 SM4 密钥 → 解密 userSeed → 计算种子 → 生成 TOTP。
func (f *Forge) forge(sn, username, randomNum, userSeedB64 string, tsMs int64) (*Result, error) {
	if f.LocalKey == nil {
		return nil, fmt.Errorf("local key is not set")
	}
	sm4Key := f.deriveKey(randomNum)
	part1, part2, err := f.decryptUserSeed(userSeedB64, sm4Key)
	if err != nil {
		return nil, err
	}
	seed := sm3Hash([]byte(part1 + part2))
	counter := tsMs / 60000
	return &Result{
		SN:          sn,
		Username:    username,
		RandomNum:   randomNum,
		UserSeedB64: userSeedB64,
		SM4KeyHex:   hex.EncodeToString(sm4Key),
		Part1:       part1,
		Part2:       part2,
		SeedHex:     hex.EncodeToString(seed),
		Counter:     counter,
		OTP:         guomiTOTP(seed, counter, 6),
		NextOTP:     guomiTOTP(seed, counter+1, 6),
	}, nil
}

// deriveKey 派生 SM4 密钥：HMAC-SM3(key=randomNumber, data=LOCAL_KEY)[:16]。
func (f *Forge) deriveKey(randomNum string) []byte {
	return hmacSM3([]byte(randomNum), f.LocalKey)[:16]
}

// decryptUserSeed 解密 userSeed → "part1|part2"。
func (f *Forge) decryptUserSeed(userSeedB64 string, sm4Key []byte) (string, string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(userSeedB64))
	if err != nil {
		return "", "", fmt.Errorf("userSeed base64 decode: %w", err)
	}
	plaintext, err := sm4ECBDecrypt(ciphertext, sm4Key)
	if err != nil {
		return "", "", fmt.Errorf("userSeed sm4 decrypt: %w", err)
	}
	text := string(plaintext)
	parts := strings.Split(text, "|")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("decrypt result format error: %q", text)
	}
	return parts[0], parts[1], nil
}
