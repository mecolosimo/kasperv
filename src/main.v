module main


import encoding.hex
//import io
import os
//import os.input
import crypto.md5
import readline { read_line }
import regex
//import strings

const sit5_archiveversion = 5
const sit5_id = [0xA5, 0xA5, 0xA5,0xA5]
const sit5_archiveflags_14bytes = 0x10 	
const sit5_archiveflags_20bytes = 0x20
const sit5_archiveflags_crypted = 0x80
const sit5_key_length = 5 /* 40 bits */


fn stuffit_md5(data []u8) ![]u8 {
	mut sum := md5.sum(data).hex()
	println("stuffit_MD5: ${sum} ${sum.bytes()}")
	// bytes is wrong
	mut stuffit := hex.decode(sum) or { panic('${err}') }
	return stuffit[..sit5_key_length]
}

fn kasper(passwd string, sit_file string) ![]u8 {

	mut sit_file_cwd := os.abs_path(sit_file)
	// debug
	println(sit_file_cwd)

	if !os.exists(sit_file_cwd) {
		return error("SIT source path doesn't exist")
	}

	mut f := os.open(sit_file_cwd) or { panic('${err}') }

	// Read header
 	m := r'StuffIt'
 	mut re := regex.regex_opt(m) or { panic('${err}') }
	// Read "magic" bytes.
	l := f.read_bytes(7)
	mut line := l.bytestr()

	sit5 := re.matches_string(line)
	if !sit5 {
		return error("Not a SIT5 archive!")
	}

	f.seek(i64(sizeof(u8))*82, .start) or { panic('${err}') } // skip to version, 0x52
	version := f.read_raw[u8]() or { panic('${err}') }
	flags := f.read_raw[u8]() or { panic('${err}') }
	// degbug
	println("flags: ${flags}")

	if version != sit5_archiveversion {
		panic('NOT SIT version 5')
	}

	//fseek := 16 // v's file method are odd can't use read_bytes with seek!
	f.seek(i64(sizeof(u8))*16, .current) or { panic('${err}')}
	if flags&sit5_archiveflags_14bytes != 0{
		f.seek(i64(sizeof(u8))*14, .current) or { panic('${err}') }
		//fseek += 14
	}

	if flags&sit5_archiveflags_20bytes != 0 {
		// skip over comment
		f.seek(i64(sizeof(u32)), .current) or { panic('${err}') }
		//fseek += 32
	}

	if flags&sit5_archiveflags_crypted == 0 {
		// move this to an else
		panic("Not encrypted!")
	}

	// Read encrypted password
	hash_size := f.read_raw[u8]() or { panic("${err}")}
	if hash_size != sit5_key_length {
		panic("hashed key length wrong ${hash_size.hex()}!")
	}
	// v's file utils suck
	mut archive_hash := []u8{len: 0, cap: sit5_key_length, init: 0}
	for i :=0; i < sit5_key_length; i++ {
		archive_hash << f.read_raw[u8]() or { panic("${err}")}
	}
	println("archive_hash: ${archive_hash}")

	mut archive_key := stuffit_md5(passwd.bytes()) or { panic('${err}') }
	mut hash := stuffit_md5(archive_key) or { panic('${err}')}

	// debugging
	println("password: ${passwd} ${passwd.bytes()}")
	println("md5 archive_key ${archive_key.hex()} ${archive_key}")
	println("md5 hash: ${hash}")

	return hash
}

fn main() {
	println('Kasper: a sit5 password recovery tool.')
	println('')

	// How to make a variable in v?
	mut password_text := []string{}
	mut sit5_file := []string{}

	if os.args.len == 3 {
		// get file name
		sit5_file << os.args[1]
		// get password
		password_text << os.args[2]
	} else if os.args.len == 2 {
		// get file name from args
		sit5_file << os.args[1]

		// ask for password
		password_text << read_line("Enter password:") or { panic('${err}') }
		//println(password.len)
	} else {
		panic('Error: incomplete command')
	}

	sit5_file[0] = sit5_file[0].trim_space()

	if sit5_file[0].trim_space().len == 0 {
		panic("No sit!")
	}
	
	res := kasper(password_text[0], sit5_file[0]) or { panic('${err}') }
   
	println(res)
}