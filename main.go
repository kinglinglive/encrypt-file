package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// 最大密钥长度
const maxKeySize = 32
const bufferSize = 1024 * 1024 // 1MB

// 处理密钥（截断或填充到 32 字节）
func processKey(key string) []byte {
	keyBytes := []byte(key)
	if len(keyBytes) > maxKeySize {
		return keyBytes[:maxKeySize] // 截断
	}
	paddedKey := make([]byte, maxKeySize)
	copy(paddedKey, keyBytes) // 自动填充
	return paddedKey
}

// 生成随机 IV
func generateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

// 显示进度
func printProgress(processed, total int64) {
	percent := float64(processed) / float64(total) * 100
	fmt.Printf("\r进度: %.2f%%", percent)
}

// AES-256-CFB 加密
func encryptFile(key, inputFile, outputFile string) error {
	in, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	// 计算文件大小
	fileInfo, err := in.Stat()
	if err != nil {
		return err
	}
	totalSize := fileInfo.Size()

	block, err := aes.NewCipher(processKey(key))
	if err != nil {
		return err
	}

	iv, err := generateIV()
	if err != nil {
		return err
	}
	_, err = out.Write(iv) // 先写入 IV
	if err != nil {
		return err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	buffer := make([]byte, bufferSize)
	var processed int64

	for {
		n, err := in.Read(buffer)
		if n > 0 {
			stream.XORKeyStream(buffer[:n], buffer[:n])
			if _, err := out.Write(buffer[:n]); err != nil {
				return err
			}
			processed += int64(n)
			printProgress(processed, totalSize)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	fmt.Println("\n加密完成!")
	return nil
}

// AES-256-CFB 解密
func decryptFile(key, inputFile, outputFile string) error {
	in, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	// 计算文件大小
	fileInfo, err := in.Stat()
	if err != nil {
		return err
	}
	totalSize := fileInfo.Size() - aes.BlockSize

	block, err := aes.NewCipher(processKey(key))
	if err != nil {
		return err
	}

	// 读取 IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(in, iv); err != nil {
		return err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	buffer := make([]byte, bufferSize)
	var processed int64

	for {
		n, err := in.Read(buffer)
		if n > 0 {
			stream.XORKeyStream(buffer[:n], buffer[:n])
			if _, err := out.Write(buffer[:n]); err != nil {
				return err
			}
			processed += int64(n)
			printProgress(processed, totalSize)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	fmt.Println("\n解密完成!")
	return nil
}

func main() {
	decryptMode := flag.Bool("d", false, "解密模式")
	flag.Parse()
	args := flag.Args()

	if len(args) < 2 {
		fmt.Println("用法:")
		fmt.Println("加密: king-encrypt 密钥 要加密的文件 [加密后的文件名]")
		fmt.Println("解密: king-encrypt -d 密钥 已加密文件 [解密后的文件名]")
		os.Exit(1)
	}

	key := args[0]
	inputFile := args[1]
	var outputFile string

	if len(args) > 2 {
		outputFile = args[2]
	} else {
		if *decryptMode {
			outputFile = strings.TrimSuffix(inputFile, "_encrypted")
		} else {
			outputFile = inputFile + "_encrypted"
		}
	}

	if *decryptMode {
		fmt.Println("正在解密文件:", inputFile)
		err := decryptFile(key, inputFile, outputFile)
		if err != nil {
			fmt.Println("解密失败:", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("正在加密文件:", inputFile)
		err := encryptFile(key, inputFile, outputFile)
		if err != nil {
			fmt.Println("加密失败:", err)
			os.Exit(1)
		}
	}
}
