// Copyright (c) 2025 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module sit

import progressbar

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

fn check_sit5_password_internal(passwd string, config SitConfig) string {
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
	}

	if hash == config.archive_hash {
		return passwd
	}
	return ""
}

pub fn check_sit5_password(config SitConfig, mut pb progressbar.Progessbar) []string {
	return replace_asterix(config, mut pb, check_sit5_password_internal)
}
