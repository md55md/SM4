package SM4_Tab

func xor(in, iv []byte) (out []byte) {
	//uint32可以相互异或，但是[]byte之间不可以
	if len(in) != len(iv) {
		return nil
	}
	out = make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		out[i] = in[i] ^ iv[i]
	}
	return out
	//这里的out为什么可以省略？
}

func InitalBlock(b []uint32, block []byte) {
	//将16字节的密钥改为4个字类型的uint32
	for i := 0; i < 4; i++ {
		b[i] = (uint32(block[i*4]) << 24) | (uint32(block[i*4+1]) << 16) |
			(uint32(block[i*4+2]) << 8) | (uint32(block[i*4+3]))
	}
}

func permuteFinalBlock(b []byte, block []uint32) {
	for i := 0; i < 4; i++ {
		b[i*4] = uint8(block[i] >> 24)
		b[i*4+1] = uint8(block[i] >> 16)
		b[i*4+2] = uint8(block[i] >> 8)
		b[i*4+3] = uint8(block[i])
	}
}
func rl(x uint32, i uint8) uint32 {
	//循环左移动i位
	return (x << (i % 32)) | (x >> (32 - (i % 32)))
}
func l0(b uint32) uint32 {
	return b ^ rl(b, 13) ^ rl(b, 23)
}
func l1(b uint32) uint32 {
	return b ^ rl(b, 2) ^ rl(b, 10) ^ rl(b, 18) ^ rl(b, 24)
}

func feistel0(x0, x1, x2, x3, rk uint32) uint32 { return x0 ^ l0(p(x1^x2^x3^rk)) }

func f(x0, x1, x2, x3, rk uint32) uint32 {
	//F的操作
	return x0 ^ l1(p(x1^x2^x3^rk))
}
func p(a uint32) uint32 {
	//非线性变换，传入的是一个字=4个字节，返回的也是一个字=四个字节
	//s 盒
	return (uint32(sbox[a>>24]) << 24) ^ (uint32(sbox[(a>>16)&0xff]) << 16) ^ (uint32(sbox[(a>>8)&0xff]) << 8) ^ uint32(sbox[(a)&0xff])
}
func GencsubKeys(key []byte) []uint32 {
	subkeys := make([]uint32, 32) //make申请内存
	b := make([]uint32, 4)
	InitalBlock(b, key) //key是16byte的key，转为4个字
	b[0] ^= fk[0]
	b[1] ^= fk[1]
	b[2] ^= fk[2]
	b[3] ^= fk[3] //初始化密钥
	for i := 0; i < 32; i++ {
		subkeys[i] = feistel0(b[0], b[1], b[2], b[3], ck[i])
		b[0], b[1], b[2], b[3] = b[1], b[2], b[3], subkeys[i]
	}
	return subkeys
}

func CryptBlock(subkeys []uint32, b []uint32, r []byte, src []byte, decrypt bool) []byte {
	InitalBlock(b, src)
	_ = b[3]
	if decrypt {
		for i := 0; i < 8; i++ {
			s := subkeys[31-4*i-3 : 31-4*i-3+4]
			x := b[1] ^ b[2] ^ b[3] ^ s[3]
			b[0] = b[0] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[2] ^ b[3] ^ s[2]
			b[1] = b[1] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[1] ^ b[3] ^ s[1]
			b[2] = b[2] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[1] ^ b[2] ^ b[0] ^ s[0]
			b[3] = b[3] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
		}
	} else {
		for i := 0; i < 8; i++ {
			s := subkeys[4*i : 4*i+4]
			x := b[1] ^ b[2] ^ b[3] ^ s[0]
			b[0] = b[0] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[2] ^ b[3] ^ s[1]
			b[1] = b[1] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[1] ^ b[3] ^ s[2]
			b[2] = b[2] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[1] ^ b[2] ^ b[0] ^ s[3]
			b[3] = b[3] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
		}
	}
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
	permuteFinalBlock(r, b)
	return r
}
