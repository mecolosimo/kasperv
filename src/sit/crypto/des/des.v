// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
// Derived from Unarchiver/XADMaster/XADStuffItDESHandle.m
module des

import bytes

type aInt8 = []int{len: 8}
type aaInt16_2 [][]int{len 16, init: []int{len: 2}

struct StuffItDESKeySchedule {
pub:
	subkeys		aaInt16_2	// seems v does like double initialing here, but types are okay
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

fn stuffit_des_crypt(mut data []u8{len: 8},
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

[@inline]
fn nibble(key aInt8, n int) u32 {
	return u32( (key[n & 0x0f] >> 1 (((n ^ 1) & 1) << 2)) & 0x0f)
}

// Takes mut []int len 8
fn stuffit_des_setkey(mut key aInt8,
											mut &ks StuffItDESKeySchedule) { // was, StuffItDESSetKey
	for i := 0; i < 16 ; i++ {
		mut subkey1 := u32((nibble(key, i) >> 2) | (nibble(key, i + 13) << 2))
		subkey1 |= ((nibble(key, i + 11) >> 2) | (nibble(key, i + 6) << 2)) << 8
		subkey1 |= ((nibble(key, i + 3) >> 2) | (nibble(key, i + 10) << 2)) << 16
		subkey1 |= ((nibble(key, i + 8) >> 2) | (nibble(key, i + 1) << 2)) << 24
		mut subkey0 := u32((nibble(key, i + 9) | nibble(key, i) << 4) & 0x3f)
		subkey0 |= ((nibble(key,i + 2) | (nibble(key,i + 11) << 4)) & 0x3f) << 8
		subkey0 |= ((nibble(key,i + 14) |(nibble(key,i + 3) << 4)) & 0x3f) << 16
		subkey0 |= ((nibble(key,i + 5) | (nibble(key,i + 8) << 4)) & 0x3f) << 24

		// This is a little-endian DES implementation, so in order to get the
		// key schedule right, we need to bit-reverse and swap the even/odd
		// subkeys. This is not needed for a regular DES implementation.
		subkey0 = reverse_bits(subkey0)
		subkey1 = reverse_bits(subkey1)

		ks.subkeys[i][0] = subkey1
		ks.subkeys[i][1] = subkey0
	}
}

// Calculate archive key and IV from password and mkey
pub fn key_for_password_data(password string, entrykey string, mkey ?string) ?[]u8 {
	ks	&StuffItDESKeySchedule

	if mk := mkey { // not none, XADStuffitParser ONLY calls this if not none, see decryptHandleForEntryWithDictionary
		if mk.len != 8 {
			// Depends on len 8 below
			panic("mkey is not length 8!")
		}
	} else {
		panic("mkey is not set!")
	}

	// Weirdly not checked in orignal
	if entrykey.len < 16 {
		panic("entrykey length less than 16!")
	}

	length := password.len
	if length > 8 {
		panic("password length > 8!")
	}

	// Is ther a better way?
	passblock := [u8(0),0,0,0,0,0,0]
	for i, l in password {
		passblock[i] = l
	}

	archivekey := []u8{len: 8}
	archiveiv  := []u8{len: 8}

	initialkey := [u8(0x01), 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
	for i := 0; i < 8; i++ {
		archivekey[i] = initialkey[i]^(passblock[i]&0x7f)
	}

	stuffit_des_setkey(initialkey,&ks)
	stuffit_des_crypt(archivekey,&ks,true)

	// copy mk into achiveiv
	for i := 0; i < 8; i++ {
		archiveiv[i] = mkey[i]
	}

	// Calculate file key and IV from entrykey, archive key and IV.
	filekey := entrykey.bytes()[ .. 8]
	fileiv := entrykey.bytes()[8 .. 16]
	//unsafe { vmemcpy(&filekey.addr[0], &entrykey.bytestr().addr[0], 8) }
	//unsafe { vmemcpy(&fileiv,&entrykey[8:].bytestr().addr[0], 8) }

	stuffit_des_setkey(archivekey,&ks)
	stuffit_des_crypt(verifyblock,&ks,true)

	if verifyblock[4:] != archiveiv[4:] {
		return none
	}

	stuffit_des_setkey(archivekey,&ks)
	stuffit_des_crypt(filekey,&ks,false)

	for i := 0; i < 8; i++ {
		filekey[i] ^= archiveiv[i]
	}

	stuffit_des_setkey(filekey,&ks)
	stuffit_des_crypt(fileiv,&ks,false)

	key := filekey.bytes[ .. 8]
	key << fileiv.bytes[ .. 8]
	return key
}
