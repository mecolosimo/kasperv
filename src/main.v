// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module main

import crypto.md5
import encoding.hex
import flag
import io
import os
import regex
import time

import sit

const sit5_archiveversion = 5
const sit5_id = [0xA5, 0xA5, 0xA5,0xA5]
const sit5_archiveflags_14bytes = 0x10 	
const sit5_archiveflags_20bytes = 0x20
const sit5_archiveflags_crypted = 0x80
const sit5_key_length = 5 /* 40 bits */

const debug = true

@[xdoc: 'Kasper: a sit5 password recovery tool.']
@[version: '0.0.2']
@[name: 'kasper']
struct Config {
	passwd		string 	@[short: p; xdoc: 'The password to try']
	file		string 	@[short: f; xdoc: 'A password file with a password per line']
	sit			string 	@[short: s; xdoc: 'The password protected SIT archive']
	wildcard 	bool 	@[short: w; xdoc: 'Expand astericks in passwd']
	help 		bool 	@[short: h; xdoc: 'Help']
	debug		bool 	@[short: d; xdoc: 'Debug']
}

struct SitConfig {
pub:
	sit				string
	archive_hash	[]u8
	wildcard 		bool
	debug			bool
pub mut:
	passwd			string
	index 			int = -1		@[xdoc: 'the index position of an asterix in the passwd']
}


// index_after returns the position of the input string p, 
// starting search from `from_index` position.
@[direct_array_access]
fn index_of(s string, p string, from_index ?int) ?int {
	// based v's index_of and on https://docs.oracle.com/javase/6/docs/api/java/lang/String.html#indexOf(java.lang.String,%20int)
	// and https://docs.python.org/3/library/stdtypes.html#str.find
	// see issue #804
	mut strt := 0
	if from_index != none {
		strt = from_index
		if strt < 0 {
			strt = 0
		}
	}
	if p.len > s.len {
			return none
	}
	if strt >= s.len {
			return none
	}
	mut i := strt
	for i < s.len {
			mut j := 0
			mut ii := i
			for j < p.len &&
				ii < s.len &&
				unsafe { s.str[ii] == p.str[j] } {
					j++
					ii++
			}
			if j == p.len {
					return i
			}
			i++
	}
	return none
}

@[inline]
fn stuffit_md5(data []u8) ![]u8 {
	mut sum := md5.sum(data).hex()
	// sum.hex() is wrong. What is it?
	mut stuffit := hex.decode(sum) or { panic('${err}') }
	return stuffit[..sit5_key_length]
}

fn check_5_password(config SitConfig) !bool {

	passwd := config.passwd
	mut wi := config.index
	if config.wildcard && passwd.contains('*') {
		if config.index == -1 {
			// index not set
			wi = passwd.index('*') or { panic('${err}') }
		} else {
			if wi < passwd.len {
				if passwd[wi] == u8(42) && config.debug {
					println("Index at * (${wi})")
					wi = if wi >= passwd.len { passwd.len } else { wi }
				}
			}
		}
		// Are there more asterices?
		// Bad naming of function (index_after), IMHO.
		mut next_index := config.index
		if config.index == -1 {
			next_index = index_of(passwd, '*', wi) or { passwd.len }
		} else if wi < passwd.len {
			if passwd[wi] == u8(42) {
				next_index = index_of(passwd, '*', wi + 1) or {	passwd.len }
			} else {
				next_index = index_of(passwd, '*', wi) or {	passwd.len }
			}
		} 

		if wi > -1 && wi < passwd.len {
			mut m := false
			for i in 32 .. 127 { // space to ~
				byte_c := u8(i)
				mut p := passwd.bytes() // []u8, strings are not mutable
				p[wi] = byte_c
				new_passwd := p.bytestr() // back to string
				if config.debug {
					println("new_passwd: ${new_passwd}")
				}

				new_config := SitConfig{
					passwd:		 	new_passwd
					archive_hash: 	config.archive_hash
					wildcard: 		config.wildcard
					debug:			config.debug
					index: 			next_index
				}

				r := check_5_password(new_config) or { panic('${err}') }

				if r {
					m = r
				}
			}
			return m
		} // end if
	}

	mut archive_key := stuffit_md5(passwd.bytes()) or { panic('${err}') }
	mut hash := stuffit_md5(archive_key) or { panic('${err}')}

	// debugging
	if config.debug {
		println("") // for timer
		println("password: ${passwd} ${passwd.bytes()}")
		println("md5 archive_key ${archive_key.hex()} ${archive_key}")
		println("md5 hash: ${hash}")
		println("archive_hash: ${config.archive_hash}")
	}

	mut matches := false
	if hash == config.archive_hash {
		println("")
		println("Match: ${passwd}")
		return true
	}

	return matches
}

fn is_sit5(f os.File) bool {
	// Read header (XADStuffIt5Parser.c)
 	m := r'StuffIt'
 	mut re := regex.regex_opt(m) or { panic('${err}') }

	// Read "magic" bytes.
	l := f.read_bytes(7)
	mut line := l.bytestr()

	sit5 := re.matches_string(line)
	if !sit5 {
		return false
	} else {
		return true
	}
	return false
}

fn is_sit(f os.File) bool {
	// from XADStuffitParser.m:recognizeFileWithHandle
	mut bytes := []u8{len: 4, cap: 4, init: 0}
	f.read_bytes_into(10, mut bytes) or { panic('${err}') }

	//if(length<14) return false
	if bytes == [u8(0x72), 0x4c, 0x61, 0x75 ] { // rLau
		// looks good so far, check more
		f.read_bytes_into(0, mut bytes) or { panic('${err}') }
		if bytes == [u8(0x53), 0x49, 0x54, 0x21] {  // SIT!
			return true
		}
		// Installer archives?
		if bytes[0] == u8(83) && bytes[1] ==  u8(84) { // 'S' and 'T'
			if bytes[2] == u8(105) && (bytes[3] == u8(110) || (bytes[3] >= u8(48) && bytes[3] <= u8(57))) { // 'i' and ('n' or '0' and '9'
				return true 
			} else if bytes[2] >= u8(48) && (bytes[2] <= u8(57) && (bytes[3] >= u8(48) && bytes[3] <= u8(57))) { // 0 and ('9' and ( '0' and '9'))
				return true
			}
		}
	}
	return false
}

// run kasper on sit5 art archive
fn kaspser_five(config Config, mut f os.File) ! {
	mut archive_hash := []u8{len: sit5_key_length, cap: sit5_key_length, init: 0}

	f.seek(i64(sizeof(u8))*82, .start) or { panic('${err}') } // skip to version, 0x52
	version := f.read_raw[u8]() or { panic('${err}') }
	flags := f.read_raw[u8]() or { panic('${err}') }
	
	if config.debug {
		println("flags: ${flags}")
	}

	if version != sit5_archiveversion {
		panic('NOT SIT version 5')
	}

	// v's file method are odd can't use read_bytes with seek!
	f.seek(i64(sizeof(u8))*16, .current) or { panic('${err}')}
	if flags&sit5_archiveflags_14bytes != 0{
		f.seek(i64(sizeof(u8))*14, .current) or { panic('${err}') }
	}

	if flags&sit5_archiveflags_20bytes != 0 {
		// skip over comment
		f.seek(i64(sizeof(u32)), .current) or { panic('${err}') } 
	}

	if flags&sit5_archiveflags_crypted == 0 {
		panic("Not encrypted!")
	}

	// Read encrypted password
	// v's file utils suck so does c's :(
	f.read_bytes_into(u64(f.tell() or { panic('${err}') }) + 1, 
					mut archive_hash) or { panic('${err}') } 

	if config.debug {
		println("archive_hash: ${archive_hash}")
	}

	if config.passwd.len > 0 {
		println('Checking ${config.passwd}')

		kasper_config := SitConfig{
			passwd:			config.passwd
			archive_hash: 	archive_hash
			wildcard: 		config.wildcard
			debug:			config.debug
		}

		check_5_password(kasper_config) or { panic('${err}')}
	} 

	// check if password and file given is main
	if config.file.trim_space().len > 0 {
		println("Checking words in ${config.file}")

		mut file_path := os.abs_path(config.file)

		if !os.exists(file_path) {
			return error("password file path doesn't exist")
		}
		
		mut password_file := os.open(file_path) or { panic('${err}') }
		defer {
			password_file.close()
		}

		mut reader := io.new_buffered_reader(reader: password_file) // not string_builder!
		mut cnt := 0
		mut sw := time.new_stopwatch()
		sw.start()
		for {
			password := reader.read_line() or { break }	//could be cleaner
			
			if config.debug {
				println('Checking: ${password}')
			}

			kasper_file_config := SitConfig{
				passwd:			password.trim_space()
				archive_hash: 	archive_hash
				wildcard: 		false		// just use words as passwords
				debug:			config.debug
			}
		
			check_5_password(kasper_file_config) or { panic('${err}')}

			// Simple old school way of showing progress
			if cnt % 1000 == 0 {
				print("Checked ${cnt} passwords in ${sw.elapsed()}\r") 
			}

			cnt += 1
		}

		sw.stop()
		println("Checked ${cnt} total passwords in ${sw.elapsed()}") 
	}
}

fn kasper(config Config) ! {

	mut sit_file_path := os.abs_path(config.sit)

	// debug
	if config.debug {
		println(sit_file_path)
	}

	if !os.exists(sit_file_path) && os.is_file(sit_file_path) {
		return error("SIT source path doesn't exist")
	}

	mut f := os.open(sit_file_path) or { panic('${err}') }
	defer {
		f.close()
	}

	if is_sit(f) {
		println("SIT!")
		println("entrykey: ${sit.parse(mut f)!.entrykey}")
	} else if is_sit5(f) {
		kaspser_five(config, mut f)!
	}
}

fn main() {
    // Map POSIX and GNU style flags found in `os.args` to fields on struct `T`
    config, no_matches := flag.to_struct[Config](os.args, skip: 1)!

    if no_matches.len > 0 {
        println('The following flags could not be mapped to any fields on the struct: ${no_matches}')
    }

    if config.help {
        // Generate and layout (a configuable) documentation for the flags
        documentation := flag.to_doc[Config](
			fields: {
				'sit':			'This specifics the location of the password protected SIT archive'
				'file': 		'A password file with a password per line'
				'passwd':		'This is the password to try'
				'wildcard':		'This flag is to specify whether the passwd contains astericks that should be expanded'
				'debug':		'This flag is to specify whether to display debug info'
			}
		)!
		println(documentation)
		exit(0)
	}

	println('Kasper: a sit5 password recovery tool.')
	println('')

	if config.sit.trim_space().len == 0 {
		panic("No sit file given!")
	}
	
	// better way to check?
	if config.passwd.len != 0 && config.file.trim_space().len != 0 {
		panic("Expected password or file. NOT both!")
	}

	kasper(config) or { panic('${err}') }
	println("Done")
}