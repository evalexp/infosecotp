# infosecotp

离线 OTP（国密 GUOMI-TOTP）计算库 + 命令行工具。

已知本地密钥与二维码内容（或 randomNumber/userSeed 字段）即可离线计算 6 位动态口令，
无需联网。算法链路：

```
二维码 "sn|username|randomNumber|userSeed"
  → 派生 SM4 密钥      HMAC-SM3(key=randomNumber, data=LOCAL_KEY) 取前 16 字节
  → 解密 userSeed      SM4-ECB（PKCS7 填充）→ "part1|part2"
  → 计算 OTP 种子      SM3(part1 || part2) → 32 字节
  → 生成动态口令       GUOMI-TOTP(seed, counter=毫秒/60000) → 6 位
```

## 作为库引用

```sh
go get github.com/evalexp/infosecotp@v0.1.0
```

```go
import "github.com/evalexp/infosecotp/otp"

// 从二维码原始文本
res, err := otp.ForgeFromQR("sn|user|rand|userSeedB64", time.Now().UnixMilli())
fmt.Println(res.OTP)

// 从二维码图片
res, err = otp.ForgeFromImage("./qr.png", time.Now().UnixMilli())

// 已知字段直接计算（跳过二维码解析）
res, err = otp.ForgeFromParts("sn", "user", "rand", "userSeedB64", tsMs)
```

## 命令行

```
infosecotp parse --image <qr.png> [选项]                          解析二维码图片 → OTP
infosecotp parse --string <qrContent> [选项]                       用二维码内容字符串 → OTP（与 --image 互斥）
infosecotp gen --rand <randomNumber> --seed <userSeed-b64> [选项]  由已知字段直接生成 OTP

选项:
  --image <path>     二维码图片路径（PNG/JPEG/GIF），与 --string 互斥
  --string <content> 二维码内容字符串（sn|username|randomNumber|userSeed），与 --image 互斥
  --time <毫秒>      时间戳，缺省为当前机器时间
  --local-key <b64>  本地密钥（Base64），缺省使用内置默认密钥
  --verbose          打印中间值（SM4 密钥、种子碎片、OTP 种子等）
```

- `--image` 与 `--string` 互斥，二者必须提供其一（`parse` 命令）。
- `--time` 指定时间戳（毫秒），缺省为当前机器时间。
- `--local-key` 指定本地密钥（Base64），缺省使用内置默认密钥。
- `--verbose` 打印中间值（SM4 密钥、种子碎片、OTP 种子），便于排查。

```sh
go run ./cmd/infosecotp parse --image ./qr.png
go run ./cmd/infosecotp parse --string "sn001|user01|1234567890|<userSeedB64>"
go run ./cmd/infosecotp gen --rand 1234567890 --seed <b64> --time 1600000000000 --local-key <b64> --verbose
```

## 依赖

- [github.com/emmansun/gmsm](https://github.com/emmansun/gmsm) — 国密算法（SM3/SM4）
- [github.com/makiuchi-d/gozxing](https://github.com/makiuchi-d/gozxing) — 二维码解析
