// Copyright (c) 2025 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module sit

import crypto.md5
import encoding.hex

pub const sit5_key_length = 5 /* 40 bits */

@[inline]
fn stuffit_md5(data []u8) ![]u8 {
	mut sum := md5.sum(data).hex()
	// sum.hex() is wrong. What is it?
	mut stuffit := hex.decode(sum) or { panic('${err}') }
	return stuffit[..sit5_key_length]
}

pub fn check_5_password(config SitConfig) !bool {
	passwd := config.passwd
	mut wi := config.index
	if config.wildcard && passwd.contains('*') {
		if config.index == -1 {
			// index not set
			wi = passwd.index('*') or { panic('${err}') }
		} else {
			if wi < passwd.len {
				if passwd[wi] == u8(42) {
					if config.debug {
						println("Index at * (${wi})")
					}
					wi = if wi >= passwd.len { passwd.len } else { wi + 1}
				}
			}
		}
		// Are there more asterices?
		// Bad naming of function (index_after), IMHO.
		mut next_index := config.index
		if config.index == -1 {
			next_index = index_of(passwd, '*', wi) or { passwd.len }
		} else if wi < passwd.len  {
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
					println("\tnew_character: ${i}\tnew_passwd: ${new_passwd}")
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
	if config.debug && hash == config.archive_hash {
		println("")
		println("password: ${passwd} ${passwd.bytes()}")
		println("passowd len: ${passwd.len}")
		println("md5 archive_key ${archive_key.hex()} ${archive_key}")
		println("md5 hash: ${hash}")
		println("archive_hash: ${config.archive_hash}")
		println("Index: ${wi}")
	}

	if hash == config.archive_hash {
		println("")
		println("Match: ${passwd}")
		return true
	}

	return false
}
