package otp

import (
	"bytes"
	"fmt"
	"image"
	"os"

	goxing "github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// 注册常见图片格式解码器（image.Decode 依赖）
import (
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
)

// ParseQRCodeFromImage 从图片中解析二维码内容。
func ParseQRCodeFromImage(img image.Image) (string, error) {
	bitmap, err := goxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("parse qrcode: %w", err)
	}
	result, err := qrcode.NewQRCodeReader().DecodeWithoutHints(bitmap)
	if err != nil {
		return "", fmt.Errorf("parse qrcode: %w", err)
	}
	return result.GetText(), nil
}

// ParseQRCodeFromFile 从图片文件（PNG/JPEG/GIF）解析二维码内容。
func ParseQRCodeFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("decode image %s: %w", path, err)
	}
	return ParseQRCodeFromImage(img)
}
