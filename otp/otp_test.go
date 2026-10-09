package otp

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// 交叉验证向量由 Python gmssl 参考实现生成（见 /tmp/otp_vec.py 输出）。

const (
	testLocalKeyB64 = "Eykt1FZjql5InmYcv2EQvq4q1pg="
	testRand        = "18374650293847561234"
	testPart1       = "seed-part-alpha"
	testPart2       = "seed-part-beta"
)

var (
	testLocalKey = mustBase64(testLocalKeyB64)
	// HMAC-SM3(key=testRand, data=localKey)
	testHMAC   = "c4316f325487cac234c45c10c43330abbdffd556cb64f5e892636a35d00dd194"
	testSM4Key = "c4316f325487cac234c45c10c43330ab"
	// SM4-ECB(PKCS7) 加密 "seed-part-alpha|seed-part-beta"（gmssl 产物）
	testCipherB64 = "7oNv4Hx95ZPZ52bRQhHc5LrbRE3te3MwsB2orxIbNP8="
	// SM3("seed-part-alphaseed-part-beta")
	testSeed = "cd6fda7d8b12136f3ccc3bf8e28f994bcba6200290e62f3bb22e04952b98bf0e"
)

func TestSM3KnownVector(t *testing.T) {
	// GM/T 0004-2012 标准向量
	if got := hex.EncodeToString(sm3Hash([]byte("abc"))); got != "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" {
		t.Fatalf("SM3(abc) mismatch: got %s", got)
	}
}

func TestHMACSM3MatchesPythonGMSSL(t *testing.T) {
	got := hex.EncodeToString(hmacSM3([]byte(testRand), testLocalKey))
	if got != testHMAC {
		t.Fatalf("HMAC-SM3 mismatch:\n got %s\nwant %s", got, testHMAC)
	}
}

func TestSM4ECBDecryptMatchesPythonGMSSL(t *testing.T) {
	ct, err := base64.StdEncoding.DecodeString(testCipherB64)
	if err != nil {
		t.Fatalf("decode ct: %v", err)
	}
	key, err := hex.DecodeString(testSM4Key)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	pt, err := sm4ECBDecrypt(ct, key)
	if err != nil {
		t.Fatalf("sm4 ecb decrypt: %v", err)
	}
	want := testPart1 + "|" + testPart2
	if string(pt) != want {
		t.Fatalf("sm4 ecb decrypt mismatch: got %q want %q", pt, want)
	}

	// Go 侧加密 → 解密 round-trip
	ct2, err := sm4ECBEncrypt([]byte(want), key)
	if err != nil {
		t.Fatalf("sm4 ecb encrypt: %v", err)
	}
	pt2, err := sm4ECBDecrypt(ct2, key)
	if err != nil {
		t.Fatalf("sm4 ecb decrypt round-trip: %v", err)
	}
	if string(pt2) != want {
		t.Fatalf("sm4 ecb round-trip mismatch: got %q want %q", pt2, want)
	}
}

func TestGuomiTOTPMatchesPythonReference(t *testing.T) {
	seed, err := hex.DecodeString(testSeed)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	cases := []struct {
		counter int64
		want    string
	}{
		{26666666, "628291"}, // ts=1600000000000
		{26666667, "937291"}, // 下一周期
		{28333333, "822270"}, // ts=1700000000000
		{28333334, "368443"},
	}
	for _, c := range cases {
		if got := guomiTOTP(seed, c.counter, 6); got != c.want {
			t.Errorf("guomiTOTP(counter=%d): got %s want %s", c.counter, got, c.want)
		}
	}
}

func TestForgeFromPartsFullFlow(t *testing.T) {
	seedB64 := testCipherB64
	qr := "sn-001|user01|" + testRand + "|" + seedB64
	f := New()
	res, err := f.ForgeFromQR(qr, 1600000000000)
	if err != nil {
		t.Fatalf("ForgeFromQR: %v", err)
	}
	if res.SN != "sn-001" || res.Username != "user01" || res.RandomNum != testRand {
		t.Errorf("parse fields mismatch: %+v", res)
	}
	if res.SM4KeyHex != testSM4Key {
		t.Errorf("sm4 key: got %s want %s", res.SM4KeyHex, testSM4Key)
	}
	if res.Part1 != testPart1 || res.Part2 != testPart2 {
		t.Errorf("seed parts: got %q|%q", res.Part1, res.Part2)
	}
	if res.SeedHex != testSeed {
		t.Errorf("seed: got %s want %s", res.SeedHex, testSeed)
	}
	if res.Counter != 26666666 {
		t.Errorf("counter: got %d want 26666666", res.Counter)
	}
	if res.OTP != "628291" {
		t.Errorf("OTP: got %s want 628291", res.OTP)
	}
	if res.NextOTP != "937291" {
		t.Errorf("NextOTP: got %s want 937291", res.NextOTP)
	}

	// ForgeFromParts 应与 ForgeFromQR 结果一致
	res2, err := f.ForgeFromParts("sn-001", "user01", testRand, seedB64, 1600000000000)
	if err != nil {
		t.Fatalf("ForgeFromParts: %v", err)
	}
	if res2.OTP != res.OTP || res2.SeedHex != res.SeedHex {
		t.Errorf("ForgeFromParts mismatch: %+v vs %+v", res2, res)
	}
}

func TestParseQRContentErrors(t *testing.T) {
	if _, _, _, _, err := ParseQRContent("a|b"); err == nil {
		t.Fatal("expected error for 2-field content")
	}
	if _, _, _, _, err := ParseQRContent("a|b|c|d|e"); err != nil {
		t.Fatalf("5 fields should be tolerated (first 4 used): %v", err)
	}
}
