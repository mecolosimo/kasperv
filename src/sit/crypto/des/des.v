// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
// Derived from Unarchiver/XADMaster/XADStuffItDESHandle.m
module des

import bytes

struct StuffItDESKeySchedule {
pub:
	subkeys		[][]int{len: 16, init: []int{len: 2}}
}

// StuffItDES is a modified DES that ROLs the input, does the DES rounds
// without IP, then RORs result.  It also uses its own key schedule.
// It is only used for key management.
fn reverse_bits(val u32) u32 {
	mut res := u32(0)
	mut v := val
	for i := 0; i < 32; i++ {
		res <<= 1
		res |= v & 1
		v >>= 1
	}
	return res
}

@[inline]
fn rotate_right(val u32, n int) u32 {
	return (val >> n) + ( val << ( 32-n ) )
}


pub fn stuffit_des_crypt(mut data []u8{len: 8},
						 	&ks StuffItDESKeySchedule,
							enc bool) {
	mut left 	:= reverse_bits(bytes.uint_32_be(data, 0)
	mut right := reverse_bits(bytes.uint_32_be(data, 4))

	right = rotate_right(right, 29)
	left  = rotate_right(left, 29)

	if enc {
		// encrypt
		for i := 0; i < 16; i += 2 {
			encrypt(mut left, right, ks.subkeys[i])	// was, Encrypt(&left,right,ks->subkeys[i]);
			encrypt(mut right, left, ks.subkeys[i+1])
		}
	} else {
			// decrypt
			for i := 15; i > 0 i -= 2 {
					encrypt(mut left, right, ks.subkeys[i])
					encrypt(mut right, left, ks.subkeys[i+1])
			}
	}
	left 	= rotate_right(left, 3)
	right = rotate_right(right, 3)

	bytes.be_uint_32(data, 0, reverse_bits(right))
	bytes.be_uint_32(data, 4, reverse_bits(left))
}
