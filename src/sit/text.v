// Copyright (c) 2025 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module sit

pub fn calc_samples(n int) u64 {
	// There must been an easier way
	mut sum := u64(0)
	if n == 1 {
		return 94
	} else if n < 1 {
		return 1
	} else {
		for i := 0; i < 95; i++ {
			sum += calc_samples( n - 1 )
		}
		return sum
	}
}

fn replace_asterix_at(config SitConfig, passwd string, from_index int, depth int,  
					  in_ch chan string) {
	next_index := passwd.index_after('*', from_index)

	if next_index > -1 && next_index < passwd.len {
		if config.debug {
				println('\tfound ${passwd[next_index]} at: ${next_index}\tfrom_index: ${from_index}\tdepth: ${depth}\tpasswd len: ${passwd.len}\tpaswd: ${passwd}')
		}
		for p in 32 .. 127 { // space to ~
			byte_c := u8(p)
			mut n := passwd.bytes() 	// []u8, strings are not mutable
			n[next_index] = byte_c
			new_passwd := n.bytestr() 	// back to string

			if config.debug {
				println("\t\tnew_passwd: ${new_passwd}\told_passwd: ${passwd}")
			}

			replace_asterix_at(config, new_passwd, next_index + 1, depth+1, in_ch)

		}
	} else {
		in_ch <- passwd
	}
}

pub fn replace_asterix(config SitConfig, in_ch chan string) {

	if config.passwd.contains('*') && config.wildcard {
		next_index := config.passwd.index_after('*', 0)
		if next_index > -1 && next_index < config.passwd.len {
			if config.debug {
				println('replace_asterix: found * at: ${next_index}\tdepth: 0\tpasswd len: ${config.passwd.len}\tpasswd: ${config.passwd}')
			}

			for p in 32 .. 127 { // space to ~
				byte_c := u8(p)
				mut n := config.passwd.bytes() // []u8, strings are not mutable
				n[next_index] = byte_c
				new_passwd := n.bytestr() // back to string
				if config.debug {
					println("\tnew_character: ${byte_c}\tnew_passwd: ${new_passwd}\toriginal password: ${config.passwd}")
				}
				
				replace_asterix_at(config, new_passwd, next_index + 1, 1, in_ch)
			}
		}
	} else {
		in_ch <- config.passwd
	}
}
