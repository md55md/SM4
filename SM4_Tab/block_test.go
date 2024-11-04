package SM4_Tab

import "testing"

type Sm4Cipher struct {
	subkeys []uint32 //字的切片
	block1  []uint32 //1 字 = 8 字节
	block2  []byte   //字节切片
}

func BenchmarkCryptBlock(b *testing.B) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("asdfghjklzxcvbnm")
	c := new(Sm4Cipher)
	c.subkeys = GencsubKeys(key) //密钥生成部分是对的；
	c.block1 = make([]uint32, 4)
	c.block2 = make([]byte, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CryptBlock(c.subkeys, c.block1, c.block2, plaintext, false)
	}
}
