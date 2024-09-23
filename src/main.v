module main

import os.input;
import crypto.md5
import readline { read_line }
import encoding.hex

fn hasher(digest []u8) ![]u8 {

	hex_str := "0123456789abcdef"

	mut res_hasher := []u8{len: 10, cap: 10, init: 0}
		
	res_hasher[0] = hex_str[(digest[0] >> 4) & 0xf] 
	res_hasher[1] = hex_str[(digest[0]) & 0xf]
	res_hasher[2] = hex_str[(digest[1] >> 4) & 0xf]
	res_hasher[3] = hex_str[(digest[1]) & 0xf]
	res_hasher[4] = hex_str[(digest[2] >> 4) & 0xf]
	res_hasher[5] = hex_str[(digest[2]) & 0xf]
	res_hasher[6] = hex_str[(digest[3] >> 4) & 0xf]
	res_hasher[7] = hex_str[(digest[3]) & 0xf]
	res_hasher[8] = hex_str[(digest[4] >> 4) & 0xf]
	res_hasher[9] = hex_str[(digest[4]) & 0xf] // 9

	return res_hasher
}

fn kasper(passwd string) ![]u8 {
	mut digest := md5.new()

 	digest.write(passwd.bytes()) or { panic('${err}') }
	mut digest_one := digest.sum([])
	println("md5 sum one: ${digest_one.hex()}") // .hex()
	digest.reset()
	digest.write(digest_one.hex().bytes()) or { panic('$err')}
	mut digest_two := md5.sum([])

	println("md5 one sum: ${digest_one[..5]}")
	println("md5 sum two: ${digest_two.hex()}")

	mut res_hasher := hasher(digest_two) or { panic('${err}') }
	println('hasher: ${res_hasher}')

	md_string4 := hex.encode(res_hasher) // returns a string
	//md_string4 := hex.decode(res_hasher.bytestr().join_to_string[u8]([]u8{}, ':', fn (it u8) string {it.ascii_str()})) or { panic('${err}') }
	println("hasher value: ${md_string4}")

	return res_hasher
}

fn main() {
	println('Kasper: a sit5 password recovery tool.')
	println('')

	password_text := input("Enter passwprd:")
	println(password_text.len)

	res := kasper(password_text) or { panic('${err}') }
   
	println(res)
}