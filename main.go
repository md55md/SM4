package main

import (
	"SM4/SM4_Tab"
	"fmt"
)

type Sm4Cipher struct {
	subkeys []uint32 //字的切片
	block1  []uint32 //1 字 = 8 字节
	block2  []byte   //字节切片
}

func main() {
	//首先初始化轮密钥
	//key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	//plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	key := []byte("0123456789abcdef")
	plaintext := []byte("asdfghjklzxcvbnm")
	fmt.Printf("明文：%s \n", string(plaintext))

	c := new(Sm4Cipher)
	c.subkeys = SM4_Tab.GencsubKeys(key) //密钥生成部分是对的；
	c.block1 = make([]uint32, 4)
	c.block2 = make([]byte, 16)
	cipher := SM4_Tab.CryptBlock(c.subkeys, c.block1, c.block2, plaintext, false)
	//加密正确
	plaintext = SM4_Tab.CryptBlock(c.subkeys, c.block1, c.block2, cipher, true)
	fmt.Printf("解密后明文：%s \n", string(plaintext))

	//c.subkeys = sm4pack.GencsubKeys(key) //密钥生成部分是对的；
	//c.block1 = make([]uint32, 4)
	//c.block2 = make([]byte, 16)
	//cipher := sm4pack.EncryptBlock(c.subkeys, c.block1, c.block2, plaintext, false)
	////加密正确
	//plaintext = sm4pack.EncryptBlock(c.subkeys, c.block1, c.block2, cipher, true)
	//fmt.Printf("解密后明文：%s \n", string(plaintext))

}
