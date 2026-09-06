// esigncert 命令行工具：把 p12 + mobileprovision 打包成 ESign 可导入的 .esigncert，
// 或反向解析 .esigncert 导出 p12 / mobileprovision。
//
// 用法:
//
//	打包： esigncert build [-p <密码>] [-o out.esigncert] cert.p12 profile.mobileprovision
//	解析： esigncert parse sample.esigncert
//
// 它只是 esigncert 库的一个最小调用示例，业务侧可直接 import 库。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"esigncert"
)

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "build":
		runBuild(os.Args[2:])
	case "parse":
		runParse(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `用法:
  esigncert build [-p <密码>] [-o out.esigncert] cert.p12 profile.mobileprovision
  esigncert parse sample.esigncert
`)
	os.Exit(2)
}

// parseFlags 手动解析 -p/-o（允许出现在位置参数前后），返回其余参数。
func parseFlags(args []string) (password, out string, rest []string) {
	password = "1"
	next := func(i int) (string, int) {
		if i+1 >= len(args) {
			usage()
		}
		return args[i+1], i + 1
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-p" || a == "--password":
			password, i = next(i)
		case a == "-o" || a == "--out":
			out, i = next(i)
		case strings.HasPrefix(a, "-p="):
			password = a[len("-p="):]
		case strings.HasPrefix(a, "--password="):
			password = a[len("--password="):]
		case strings.HasPrefix(a, "-o="):
			out = a[len("-o="):]
		case strings.HasPrefix(a, "--out="):
			out = a[len("--out="):]
		case a == "-h" || a == "--help":
			usage()
		default:
			rest = append(rest, a)
		}
	}
	return
}

func runBuild(args []string) {
	password, out, files := parseFlags(args)
	if len(files) != 2 {
		usage()
	}
	p12, err := os.ReadFile(files[0])
	die(err)
	mp, err := os.ReadFile(files[1])
	die(err)

	data, err := esigncert.Build(p12, mp, password)
	die(err)

	path := out
	if path == "" {
		path = strings.TrimSuffix(filepath.Base(files[0]), filepath.Ext(files[0])) + ".esigncert"
	}
	die(os.WriteFile(path, data, 0o644))
	fmt.Printf("OK -> %s (%d bytes), p12 password embedded: %s\n", path, len(data), password)
}

func runParse(args []string) {
	if len(args) != 1 {
		usage()
	}
	data, err := os.ReadFile(args[0])
	die(err)
	c, err := esigncert.Parse(data)
	die(err)

	base := strings.TrimSuffix(args[0], filepath.Ext(args[0]))
	die(os.WriteFile(base+".p12", c.P12, 0o644))
	die(os.WriteFile(base+".mobileprovision", c.Mobileprovision, 0o644))
	fmt.Printf("%s -> %s.p12 , %s.mobileprovision , password=%q\n", args[0], base, base, c.Password)
}
