package otp

import (
	"encoding/base64"
	"fmt"
)

// defaultLocalKeyB64 离线 OTP 计算使用的固定本地密钥（Base64）。
// 注意：该密钥是离线计算算法的共享秘密，请勿随包外泄。
const defaultLocalKeyB64 = "Eykt1FZjql5InmYcv2EQvq4q1pg="

var defaultLocalKey = mustBase64(defaultLocalKeyB64)

func mustBase64(s string) []byte {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// 编译期已知的常量，仅在密钥被改成非法 Base64 时触发
		panic(fmt.Sprintf("otp: invalid default local key: %v", err))
	}
	return key
}

// DefaultLocalKey 返回内置本地密钥（解码后的字节副本）。
func DefaultLocalKey() []byte {
	key := make([]byte, len(defaultLocalKey))
	copy(key, defaultLocalKey)
	return key
}
