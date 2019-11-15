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

	//解密开始
	tempFile, temErr := ioutil.ReadDir(filepath.Join(path, "temp"))
	if temErr != nil {
		panic(temErr)
	}
	//创建解密目录
	_, deStat := os.Stat(filepath.Join(path, "temp", "origin"))
	if deStat != nil || os.IsNotExist(deStat) {
		_ = os.Mkdir(filepath.Join(path, "temp", "origin"), os.ModePerm)
	}
	for _, temp := range tempFile {
		if !temp.IsDir() && strings.Contains(temp.Name(), ".txt") {
			if bytes, err := ioutil.ReadFile(filepath.Join(path, "temp", temp.Name())); err == nil {
				//开始解密
				by, err := base64.StdEncoding.DecodeString(string(bytes))
				if err != nil {
					panic(err)
				}
				if len(by) >= 10*aes.BlockSize {
					buff := bytes2.Buffer{}
					bic, er := aesDecrypt(string(by[:236]), getKey())
					if er != nil {
						panic(er)
					}
					buff.Write(bic)
					buff.Write(by[236:])
					by = buff.Bytes()
				}
				_ = ioutil.WriteFile(filepath.Join(path, "temp", "origin", temp.Name()), by, temp.Mode())

			}
		}
	}

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
