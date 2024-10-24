module main


import encoding.hex
import flag
//import io
import os
//import os.input
import crypto.md5
import regex
//import strings

const sit5_archiveversion = 5
const sit5_id = [0xA5, 0xA5, 0xA5,0xA5]
const sit5_archiveflags_14bytes = 0x10 	
const sit5_archiveflags_20bytes = 0x20
const sit5_archiveflags_crypted = 0x80
const sit5_key_length = 5 /* 40 bits */

const debug = true

@[xdoc: 'Kasper: a sit5 password recovery tool.']
@[version: '0.0.1']
@[name: 'kasper']
struct Config {
	passwd		string @[short: p; xdoc: 'The password to try']
	sit			string @[short: s; xdoc: 'The password protected SIT archive']
	wildcard 	bool @[short: w; xdoc: 'Expand astericks in passwd']
	help 		bool @[short: h; xdoc: 'Help']
	debug		bool @[short: d; xdoc: 'Debug']
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

fn check_password(config SitConfig) !bool {

	passwd := config.passwd
	if config.wildcard && passwd.contains('*') {
		mut wi := -1
		if config.index == -1 {
			// index not set
			wi = passwd.index('*') or { panic('${err}') }
		} else {
			wi = config.index
			if wi < passwd.len {
				if passwd[wi] == u8(42) && config.debug {
					println("Index at *")
				}
			}
		}

		// Are there more asterices?
		// Bad naming of function, IMHO.
		mut index := passwd.len
		if wi < passwd.len {
			index = index_of('passwd', '*', wi) or {
				passwd.len
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
					index: 			index
				}

				r := check_password(new_config) or { panic('${err}')}

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
		println("password: ${passwd} ${passwd.bytes()}")
		println("md5 archive_key ${archive_key.hex()} ${archive_key}")
		println("md5 hash: ${hash}")
		println("archive_hash: ${config.archive_hash}")
	}

	mut matches := false
	if hash == config.archive_hash {
		println("Match: ${passwd}")
		return true
	}

	return matches
}

fn kasper(config Config) ! {

	mut sit_file_cwd := os.abs_path(config.sit)
	// debug
	if config.debug {
		println(sit_file_cwd)
	}

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
	mut archive_hash := []u8{len: sit5_key_length, cap: sit5_key_length, init: 0}
	
	// v's file utils suck so does c's :(
	f.read_bytes_into(u64(f.tell() or { panic('${err}') }) + 1, 
					  mut archive_hash) or { panic('${err}') }

	if config.debug {
		println("archive_hash: ${archive_hash}")
	}

	kasper_config := SitConfig{
		passwd:			config.passwd
		archive_hash: 	archive_hash
		wildcard: 		config.wildcard
		debug:			config.debug
	}
	check_password(kasper_config) or { panic('${err}')}
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
	
	kasper(config) or { panic('${err}') }
	println("Done")
}