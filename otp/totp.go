package otp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// guomiTOTP 国密 TOTP（与 Python 参考实现 guomi_totp 精确一致）。
//
// seed    — 32 字节 OTP 种子
// counter — 时间计数器（当前毫秒 / 60000）
// digits  — 口令位数
func guomiTOTP(seed []byte, counter int64, digits int) string {
	// 1. counter → 8 字节大端 → hex（16 字符）
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], uint64(counter))
	counterHex := hex.EncodeToString(counterBytes[:])

	// 2. 右补 '0' 到 32 个 hex 字符
	paddedHex := counterHex
	for len(paddedHex) < 32 {
		paddedHex += "0"
	}

	// 3. seed → hex
	seedHex := hex.EncodeToString(seed)

	// 4. SM3 输入 = hex_decode(seed_hex || padded_hex)
	inputBytes, err := hex.DecodeString(seedHex + paddedHex)
	if err != nil {
		// seed 与 counter 均由 hex 编码而来，此处不会失败
		panic(fmt.Sprintf("otp: invalid hex input: %v", err))
	}
	h := sm3Hash(inputBytes) // 32 字节

	// 5. 32 字节 hash 分为 8 组 × 4 字节大端，求和
	var total int64
	for i := 0; i < 8; i++ {
		total += int64(binary.BigEndian.Uint32(h[i*4 : (i+1)*4]))
	}

	// 6. mod 2^32 → mod 10^digits → 零填充 digits 位
	otp := (total % (1 << 32)) % pow10(digits)
	return fmt.Sprintf("%0*d", digits, otp)
}

func pow10(n int) int64 {
	var r int64 = 1
	for i := 0; i < n; i++ {
		r *= 10
	}
	return r
}
