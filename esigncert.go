// Package esigncert 生成 / 解析 ESign（轻松签）可导入的 .esigncert 证书包。
//
// 格式（逆向自 ESign 4.8.2 ESign.app，已用真实导出文件做字节级验证）：
//
//	JSON 正文 = {"p12":"<base64>","mobileprovision":"<base64>","password":"<明文密码>"}
//	          序列化规则：无空格、字段顺序固定、字符串内 "/" 转义为 "\/"
//	明文     = md5(JSON正文) ‖ JSON正文
//	密文     = DES-CBC-PKCS7 加密明文
//	.esigncert 文件 = 密文原始字节（二进制，非 base64）
//
// 固定派生密钥（App 内置，各版本通用）：
//
//	S      = "yyy_cert"
//	hexmd5 = md5hex(S) = 55efcbb0b7f0706a63aeef31c0dcc341
//	DES key = hexmd5[0:8]  = "55efcbb0"（ASCII 字节）
//	DES iv  = hexmd5[8:16] = "b7f0706a"
package esigncert

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// keySource 是 App 内置常量（经多重混淆后的真实内容为 "yyy_cert"）。
const keySource = "yyy_cert"

// keyIV 派生出 DES-CBC 使用的 key 与 iv（各 8 字节 ASCII）。
func keyIV() ([]byte, []byte) {
	sum := md5.Sum([]byte(keySource))
	hex := fmt.Sprintf("%x", sum[:])
	return []byte(hex[:8]), []byte(hex[8:16])
}

// body 对应 JSON 正文。字段声明顺序即 JSON 输出顺序，必须保持
// p12 -> mobileprovision -> password 与 App 一致。
type body struct {
	P12              string `json:"p12"`
	Mobileprovision  string `json:"mobileprovision"`
	Password         string `json:"password"`
}

// serializeBody 按 ESign 自定义 JSON 序列化规则生成正文 bytes。
func serializeBody(p12B64, mpB64, password string) ([]byte, error) {
	b := body{P12: p12B64, Mobileprovision: mpB64, Password: password}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // 避免 <>& 被转成 \u003c 等
	if err := enc.Encode(b); err != nil {
		return nil, err
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	// App 侧把字符串中的 "/" 输出为 "\/"；Go 默认不转义，需手动替换。
	out = bytes.ReplaceAll(out, []byte("/"), []byte(`\/`))
	return out, nil
}

// pkcs7Pad 对 data 按 blockSize 做 PKCS7 填充。
func pkcs7Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(n)}, n)...)
}

// Build 由 p12（DER 字节）与 mobileprovision（字节）与 p12 密码，
// 生成 ESign 可导入的 .esigncert 文件字节。
// 说明：mobileprovision 无论是 DER 二进制还是 xml 文本都按原文 base64 处理。
func Build(p12, mobileprovision []byte, password string) ([]byte, error) {
	body, err := serializeBody(
		base64.StdEncoding.EncodeToString(p12),
		base64.StdEncoding.EncodeToString(mobileprovision),
		password,
	)
	if err != nil {
		return nil, fmt.Errorf("esigncert: serialize body: %w", err)
	}
	sum := md5.Sum(body)
	plain := append(sum[:], body...)
	plain = pkcs7Pad(plain, des.BlockSize)

	key, iv := keyIV()
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("esigncert: new des cipher: %w", err)
	}
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, plain)
	return encrypted, nil
}

// Cert 是 .esigncert 解析结果。
type Cert struct {
	P12             []byte // p12 DER 字节
	Mobileprovision []byte // mobileprovision 原始字节（DER 或 xml）
	Password        string // 内置 p12 明文密码
}

// Parse 解析 .esigncert 字节：DES 解密 -> 去 PKCS7 -> md5 校验 -> JSON。
func Parse(data []byte) (*Cert, error) {
	key, iv := keyIV()
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("esigncert: new des cipher: %w", err)
	}
	if len(data) == 0 || len(data)%des.BlockSize != 0 {
		return nil, fmt.Errorf("esigncert: invalid cipher length %d", len(data))
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, data)

	// 去 PKCS7 填充
	padLen := int(plain[len(plain)-1])
	if padLen == 0 || padLen > des.BlockSize || padLen > len(plain) {
		return nil, fmt.Errorf("esigncert: bad pkcs7 padding")
	}
	plain = plain[:len(plain)-padLen]

	// 前 16 字节是 md5(body)，校验完整性
	if len(plain) < 16 {
		return nil, fmt.Errorf("esigncert: plain too short")
	}
	md, bodyBytes := plain[:16], plain[16:]
	sum := md5.Sum(bodyBytes)
	if !bytes.Equal(md, sum[:]) {
		return nil, fmt.Errorf("esigncert: integrity check failed (md5 mismatch)")
	}

	var b body
	// App 侧用 "\/" 转义，标准 JSON 直接读即可（"\x2f" 语义等价）。
	if err := json.Unmarshal(bodyBytes, &b); err != nil {
		return nil, fmt.Errorf("esigncert: parse json: %w", err)
	}
	p12, err := base64.StdEncoding.DecodeString(b.P12)
	if err != nil {
		return nil, fmt.Errorf("esigncert: decode p12: %w", err)
	}
	mp, err := base64.StdEncoding.DecodeString(b.Mobileprovision)
	if err != nil {
		return nil, fmt.Errorf("esigncert: decode mobileprovision: %w", err)
	}
	return &Cert{P12: p12, Mobileprovision: mp, Password: b.Password}, nil
}
