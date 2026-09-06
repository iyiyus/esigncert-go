# esigncert-go

Go 语言实现 ESign（轻松签）`.esigncert` 证书包的**生成与解析**。纯标准库、零第三方依赖。

在签名站 / 后端服务里传入 `p12` + `mobileprovision`，即可直接产出 ESign App 可导入的证书包，将证书与描述文件内置进去，用户在 ESign 里一键导入即可签名。

## 特性

- 与 ESign App 导出的 `.esigncert` **字节级完全兼容**（已用真实 App 导出文件 + 真实证书验证）
- 双向能力：`Build` 打包 p12 + 描述文件 → `.esigncert`；`Parse` 解密 `.esigncert` → 还原 p12 / 描述文件 / 密码
- 仅依赖 Go 标准库（`crypto/des`、`crypto/md5`、`encoding/json`）
- 附带命令行工具，便于手动打包 / 解析

## 文件格式（逆向说明）

逆向自 ESign 4.8.2（`ESign.app`），格式如下：

```
JSON 正文 = {"p12":"<base64>","mobileprovision":"<base64>","password":"<明文密码>"}
           序列化规则：无空格、字段顺序固定、字符串内 "/" 转义为 "\/"
明文     = md5(JSON正文) ‖ JSON正文
密文     = DES-CBC-PKCS7 加密明文
.esigncert 文件 = 密文原始字节（二进制，非 base64）
```

固定派生密钥（App 内置，各版本通用）：

| 项 | 值 |
|---|---|
| 常量源 `S` | `yyy_cert` |
| `hexmd5 = md5hex(S)` | `55efcbb0b7f0706a63aeef31c0dcc341` |
| DES key | `hexmd5[0:8]` = `55efcbb0` |
| DES iv | `hexmd5[8:16]` = `b7f0706a` |

> 说明：密钥为 App 内置常量，这套格式不是强加密设计，本质是「App 自洽的打包格式」。请勿依赖它保护机密信息。

## 快速开始

### 作为 Go 库调用

```go
package main

import (
	"fmt"
	"os"

	"esigncert"
)

func main() {
	p12, _ := os.ReadFile("cert.p12")
	mp, _ := os.ReadFile("profile.mobileprovision")

	// 打包：password 为 p12 内置密码（ESign 通用默认 "1"）
	out, err := esigncert.Build(p12, mp, "1")
	if err != nil {
		panic(err)
	}
	os.WriteFile("cert.esigncert", out, 0o644)

	// 解析（反向）
	data, _ := os.ReadFile("cert.esigncert")
	c, err := esigncert.Parse(data)
	if err != nil {
		panic(err)
	}
	fmt.Println("password:", c.Password)
	os.WriteFile("out.p12", c.P12, 0o644)
	os.WriteFile("out.mobileprovision", c.Mobileprovision, 0o644)
}
```

### API

| 函数 | 说明 |
|---|---|
| `Build(p12, mobileprovision []byte, password string) ([]byte, error)` | 生成 `.esigncert` 文件字节 |
| `Parse(data []byte) (*Cert, error)` | 解析并校验 `.esigncert`，返回 `Cert{P12, Mobileprovision, Password}` |

`mobileprovision` 无论 DER 二进制还是 xml 文本形式都按原文处理；`p12` 须为 DER 字节。

## 命令行工具

```bash
# 打包（参数顺序随意）
go run ./cmd/esigncert build -p 1 -o cert.esigncert cert.p12 profile.mobileprovision

# 解析，导出 cert.p12 与 cert.mobileprovision
go run ./cmd/esigncert parse cert.esigncert
```

参数：

- `-p, --password`：p12 密码，默认 `1`
- `-o, --out`：输出文件名，默认 `<p12文件名>.esigncert`

## 使用建议 / 安全注意

1. 内置密码必须与发给用户的 p12 实际密码**一致**，否则 ESign 导入后无法读取私钥。
2. `.esigncert` 中 p12 的描述文件、私钥均为可逆明文存储（App 自带解包能力），请勿在不信任渠道分发。
3. 如果你在签名站做签发，建议：生成 p12 时统一密码（如 `1`）→ 用本库打包 → 把 `.esigncert` 作为下载/导入产物交给用户。

## 验证

- `go test`（roundtrip / 篡改检测 / 与 Python 参考实现字节级一致性）
- 已用 ESign 4.8.2 真实导出文件与真实 `p12 + mobileprovision` 做字节级对拍

## License

MIT
