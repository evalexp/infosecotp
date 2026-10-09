// infosecotp — 离线 OTP（国密 GUOMI-TOTP）命令行入口。
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/evalexp/infosecotp/otp"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "parse":
		err = runParse(os.Args[2:])
	case "gen":
		err = runGen(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// runParse 解析二维码图片并生成 OTP。
func runParse(args []string) error {
	fs := flag.NewFlagSet("parse", flag.ContinueOnError)
	imageFlag := fs.String("image", "", "二维码图片路径（PNG/JPEG/GIF）")
	localKey := fs.String("local-key", "", "本地密钥（Base64），缺省使用内置默认密钥")
	timeFlag := fs.Int64("time", 0, "时间戳（毫秒，0 = 当前机器时间）")
	verbose := fs.Bool("verbose", false, "打印中间值（SM4 密钥、种子碎片、OTP 种子等）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *imageFlag == "" {
		return errors.New("请提供 --image <path>")
	}
	forge, err := newForge(*localKey)
	if err != nil {
		return err
	}
	tsMs := resolveTime(*timeFlag)
	result, err := forge.ForgeFromImage(*imageFlag, tsMs)
	if err != nil {
		return err
	}
	printResult(result, tsMs, *verbose)
	return nil
}

// runGen 由已知的 randomNumber/userSeed 字段直接生成 OTP（跳过二维码解析）。
func runGen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	randFlag := fs.String("rand", "", "randomNumber 字段")
	seedFlag := fs.String("seed", "", "userSeed 字段（Base64）")
	localKey := fs.String("local-key", "", "本地密钥（Base64），缺省使用内置默认密钥")
	timeFlag := fs.Int64("time", 0, "时间戳（毫秒，0 = 当前机器时间）")
	verbose := fs.Bool("verbose", false, "打印中间值（SM4 密钥、种子碎片、OTP 种子等）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *randFlag == "" || *seedFlag == "" {
		return errors.New("--rand 与 --seed 必须同时提供")
	}
	forge, err := newForge(*localKey)
	if err != nil {
		return err
	}
	tsMs := resolveTime(*timeFlag)
	result, err := forge.ForgeFromParts("", "", *randFlag, *seedFlag, tsMs)
	if err != nil {
		return err
	}
	printResult(result, tsMs, *verbose)
	return nil
}

// newForge 根据 Base64 本地密钥创建计算器，空串使用内置默认密钥。
func newForge(localKey string) (*otp.Forge, error) {
	if localKey == "" {
		return otp.New(), nil
	}
	return otp.NewWithKey(localKey)
}

// resolveTime 时间戳（毫秒），0 表示当前机器时间。
func resolveTime(tsMs int64) int64 {
	if tsMs == 0 {
		return time.Now().UnixMilli()
	}
	return tsMs
}

// printResult 输出 OTP 结果。
func printResult(result *otp.Result, tsMs int64, verbose bool) {
	fmt.Printf("当前 OTP : %s\n", result.OTP)
	fmt.Printf("下个 OTP : %s\n", result.NextOTP)
	fmt.Printf("时间戳   : %d (counter=%d)\n", tsMs, result.Counter)
	if !verbose {
		return
	}
	fmt.Printf("sn       : %s\n", result.SN)
	fmt.Printf("username : %s\n", result.Username)
	fmt.Printf("randomNum: %s\n", result.RandomNum)
	fmt.Printf("SM4 key  : %s\n", result.SM4KeyHex)
	fmt.Printf("part1    : %s\n", result.Part1)
	fmt.Printf("part2    : %s\n", result.Part2)
	fmt.Printf("seed     : %s\n", result.SeedHex)
}

func printUsage() {
	fmt.Print(`infosecotp — 离线 OTP 计算（国密 GUOMI-TOTP）

用法:
  infosecotp parse --image <qr.png> [选项]                            解析二维码图片并生成 OTP
  infosecotp gen --rand <randomNumber> --seed <userSeed-b64> [选项]   由已知字段直接生成 OTP

选项:
  --time <毫秒>      时间戳，缺省为当前机器时间
  --local-key <b64>  本地密钥（Base64），缺省使用内置默认密钥
  --verbose          打印中间值（SM4 密钥、种子碎片、OTP 种子等）

示例:
  infosecotp parse --image ./qr.png
  infosecotp gen --rand 1234567890 --seed aGVsbG8= --time 1600000000000
`)
}
