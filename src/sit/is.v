// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module sit

import os
import regex
import bytes

pub fn is_sit5(f os.File) bool {
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

pub fn is_sit(f os.File) bool {
	// from XADStuffitParser.m:recognizeFileWithHandle
	// what versions produces this? At least 3.0.7 does.
	mut sit_bytes := []u8{len: 4, cap: 4, init: 0}
	f.read_bytes_into(10, mut sit_bytes) or { panic('${err}') }

	// if(length<14) return false
	if sit_bytes == [u8(0x72), 0x4c, 0x61, 0x75] { // rLau
		// looks good so far, check more
		f.read_bytes_into(0, mut sit_bytes) or { panic('${err}') }
		if sit_bytes == [u8(0x53), 0x49, 0x54, 0x21] { // SIT!
			return true
		}
		// Installer archives?
		if sit_bytes[0] == u8(83) && sit_bytes[1] == u8(84) { // 'S' and 'T'
			if sit_bytes[2] == u8(105) && (sit_bytes[3] == u8(110)
				|| (sit_bytes[3] >= u8(48) && sit_bytes[3] <= u8(57))) { // 'i' and ('n' or '0' and '9'
				return true
			} else if sit_bytes[2] >= u8(48) && (sit_bytes[2] <= u8(57) && (sit_bytes[3] >= u8(48)
				&& sit_bytes[3] <= u8(57))) { // 0 and ('9' and ( '0' and '9'))
				return true
			}
		}
	}
	return false
}

pub fn is_sit_zip(f os.File) bool {
	// from XADZipParser.m
	// usually with postfix of *.sit.zip
	mut sit_bytes := bytes.read_uint_32_be_at(f, 0) or { panic('${err}') }

	if sit_bytes == u32(0x504B0304) {
		// might also be 0x504b0506 for strange archives
		return true
	}
	return false
}
