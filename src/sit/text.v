// Copyright (c) 2025 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module sit

fn replace_asterix_at(config SitConfig, passwd string, from_index int, depth int, search fn (string, SitConfig) !bool) !bool {
	next_index := passwd.index_after('*', from_index)
	if next_index > -1 && next_index < passwd.len {
		if config.debug {
			println('\tfound * at: ${next_index}\tfrom_index: ${from_index}\tdepth: ${depth}\tpasswd len: ${passwd.len}\tpaswd: ${passwd}')
		}
		mut m := false
		for p in 32 .. 127 { // space to ~
			byte_c := u8(p)
			mut n := passwd.bytes() // []u8, strings are not mutable
			n[next_index] = byte_c
			new_passwd := n.bytestr() // back to string
			if config.debug {
				println("\tnew_character: ${byte_c}\tnew_passwd: ${new_passwd}\told passwd: ${passwd}")
			}
			passwd_match := replace_asterix_at(config, new_passwd, next_index + 1, depth+1, search) or { panic('$err') }
			if passwd_match {
				m = true
			}
		}
		return m
	} else {
		return search(passwd, config)
	}
}

fn replace_asterix(config SitConfig, search fn (string, SitConfig) !bool) !bool {
	if config.wildcard && config.passwd.contains('*') {
		next_index := config.passwd.index_after('*', 0)
		if next_index > -1 && next_index < config.passwd.len {
			if config.debug {
				println('\tfound * at: ${next_index}\tdepth: 0\tpasswd len: ${config.passwd.len}\tpasswd: ${config.passwd}')
			}

			mut m := false
			for p in 32 .. 127 { // space to ~
				byte_c := u8(p)
				mut n := config.passwd.bytes() // []u8, strings are not mutable
				n[next_index] = byte_c
				new_passwd := n.bytestr() // back to string
				if config.debug {
					println("\tnew_character: ${byte_c}\tnew_passwd: ${new_passwd}\told password: ${config.passwd}")
				}
				passwd_match := replace_asterix_at(config, new_passwd, next_index + 1, 1, search) or { panic('${err}')}

				if passwd_match {
					m = true
				}
			}
			return m
		}
	} else {
		return search(config.passwd, config)
	}
	return false
}
