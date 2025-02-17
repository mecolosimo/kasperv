// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
// Derived from Unarchiver/XADMaster/XADStuffItDESHandle.m
module sit

import bytes
import os

struct StuffItDESKeySchedule {
pub mut:
	subkeys		[][]u32 // Seems v does like double initialing here, but types are okay
}

// I realy don't know what the orginal is doing besides and experices in OOP

@[noinit]
struct CSInputBufferAlloc {
	bufsize			u32 = 4096			// 4k
mut:
	fh				?os.File			// Open file handle
}

@[noitit]
struct CSBlockStreamHandle {
	CSInputBufferAlloc
mut:
	streampos		u32
}

@[noinit]
struct XADStuffItDESHandle {
	CSBlockStreamHandle
	key			[]u8					@[required] // len: 16 (4 x 4 bytes)
mut:
	block		[]u8					@[required] // len: 8
	a			u32			
	b			u32						
	c			u32						
	d			u32						
	ks 			&StuffItDESKeySchedule	@[required]
}

//static const uint32_t DES_SPtrans[8][64];
const des_sptrans := [
	[
		u32(0x02080800),0x00080000,0x02000002,0x02080802,
		0x02000000,0x00080802,0x00080002,0x02000002,
		0x00080802,0x02080800,0x02080000,0x00000802,
		0x02000802,0x02000000,0x00000000,0x00080002,
		0x00080000,0x00000002,0x02000800,0x00080800,
		0x02080802,0x02080000,0x00000802,0x02000800,
		0x00000002,0x00000800,0x00080800,0x02080002,
		0x00000800,0x02000802,0x02080002,0x00000000,
		0x00000000,0x02080802,0x02000800,0x00080002,
		0x02080800,0x00080000,0x00000802,0x02000800,
		0x02080002,0x00000800,0x00080800,0x02000002,
		0x00080802,0x00000002,0x02000002,0x02080000,
		0x02080802,0x00080800,0x02080000,0x02000802,
		0x02000000,0x00000802,0x00080002,0x00000000,
		0x00080000,0x02000000,0x02000802,0x02080800,
		0x00000002,0x02080002,0x00000800,0x00080802,
	],
	[
		u32(0x40108010),0x00000000,0x00108000,0x40100000,
		0x40000010,0x00008010,0x40008000,0x00108000,
		0x00008000,0x40100010,0x00000010,0x40008000,
		0x00100010,0x40108000,0x40100000,0x00000010,
		0x00100000,0x40008010,0x40100010,0x00008000,
		0x00108010,0x40000000,0x00000000,0x00100010,
		0x40008010,0x00108010,0x40108000,0x40000010,
		0x40000000,0x00100000,0x00008010,0x40108010,
		0x00100010,0x40108000,0x40008000,0x00108010,
		0x40108010,0x00100010,0x40000010,0x00000000,
		0x40000000,0x00008010,0x00100000,0x40100010,
		0x00008000,0x40000000,0x00108010,0x40008010,
		0x40108000,0x00008000,0x00000000,0x40000010,
		0x00000010,0x40108010,0x00108000,0x40100000,
		0x40100010,0x00100000,0x00008010,0x40008000,
		0x40008010,0x00000010,0x40100000,0x00108000,
	],
	[
		u32(0x04000001),0x04040100,0x00000100,0x04000101,
		0x00040001,0x04000000,0x04000101,0x00040100,
		0x04000100,0x00040000,0x04040000,0x00000001,
		0x04040101,0x00000101,0x00000001,0x04040001,
		0x00000000,0x00040001,0x04040100,0x00000100,
		0x00000101,0x04040101,0x00040000,0x04000001,
		0x04040001,0x04000100,0x00040101,0x04040000,
		0x00040100,0x00000000,0x04000000,0x00040101,
		0x04040100,0x00000100,0x00000001,0x00040000,
		0x00000101,0x00040001,0x04040000,0x04000101,
		0x00000000,0x04040100,0x00040100,0x04040001,
		0x00040001,0x04000000,0x04040101,0x00000001,
		0x00040101,0x04000001,0x04000000,0x04040101,
		0x00040000,0x04000100,0x04000101,0x00040100,
		0x04000100,0x00000000,0x04040001,0x00000101,
		0x04000001,0x00040101,0x00000100,0x04040000,
	],
	[
		u32(0x00401008),0x10001000,0x00000008,0x10401008,
		0x00000000,0x10400000,0x10001008,0x00400008,
		0x10401000,0x10000008,0x10000000,0x00001008,
		0x10000008,0x00401008,0x00400000,0x10000000,
		0x10400008,0x00401000,0x00001000,0x00000008,
		0x00401000,0x10001008,0x10400000,0x00001000,
		0x00001008,0x00000000,0x00400008,0x10401000,
		0x10001000,0x10400008,0x10401008,0x00400000,
		0x10400008,0x00001008,0x00400000,0x10000008,
		0x00401000,0x10001000,0x00000008,0x10400000,
		0x10001008,0x00000000,0x00001000,0x00400008,
		0x00000000,0x10400008,0x10401000,0x00001000,
		0x10000000,0x10401008,0x00401008,0x00400000,
		0x10401008,0x00000008,0x10001000,0x00401008,
		0x00400008,0x00401000,0x10400000,0x10001008,
		0x00001008,0x10000000,0x10000008,0x10401000,
	],
	[
		u32(0x08000000),0x00010000,0x00000400,0x08010420,
		0x08010020,0x08000400,0x00010420,0x08010000,
		0x00010000,0x00000020,0x08000020,0x00010400,
		0x08000420,0x08010020,0x08010400,0x00000000,
		0x00010400,0x08000000,0x00010020,0x00000420,
		0x08000400,0x00010420,0x00000000,0x08000020,
		0x00000020,0x08000420,0x08010420,0x00010020,
		0x08010000,0x00000400,0x00000420,0x08010400,
		0x08010400,0x08000420,0x00010020,0x08010000,
		0x00010000,0x00000020,0x08000020,0x08000400,
		0x08000000,0x00010400,0x08010420,0x00000000,
		0x00010420,0x08000000,0x00000400,0x00010020,
		0x08000420,0x00000400,0x00000000,0x08010420,
		0x08010020,0x08010400,0x00000420,0x00010000,
		0x00010400,0x08010020,0x08000400,0x00000420,
		0x00000020,0x00010420,0x08010000,0x08000020,
	],
	[
		u32(0x80000040),0x00200040,0x00000000,0x80202000,
		0x00200040,0x00002000,0x80002040,0x00200000,
		0x00002040,0x80202040,0x00202000,0x80000000,
		0x80002000,0x80000040,0x80200000,0x00202040,
		0x00200000,0x80002040,0x80200040,0x00000000,
		0x00002000,0x00000040,0x80202000,0x80200040,
		0x80202040,0x80200000,0x80000000,0x00002040,
		0x00000040,0x00202000,0x00202040,0x80002000,
		0x00002040,0x80000000,0x80002000,0x00202040,
		0x80202000,0x00200040,0x00000000,0x80002000,
		0x80000000,0x00002000,0x80200040,0x00200000,
		0x00200040,0x80202040,0x00202000,0x00000040,
		0x80202040,0x00202000,0x00200000,0x80002040,
		0x80000040,0x80200000,0x00202040,0x00000000,
		0x00002000,0x80000040,0x80002040,0x80202000,
		0x80200000,0x00002040,0x00000040,0x80200040,
	],
	[
		u32(0x00004000),0x00000200,0x01000200,0x01000004,
		0x01004204,0x00004004,0x00004200,0x00000000,
		0x01000000,0x01000204,0x00000204,0x01004000,
		0x00000004,0x01004200,0x01004000,0x00000204,
		0x01000204,0x00004000,0x00004004,0x01004204,
		0x00000000,0x01000200,0x01000004,0x00004200,
		0x01004004,0x00004204,0x01004200,0x00000004,
		0x00004204,0x01004004,0x00000200,0x01000000,
		0x00004204,0x01004000,0x01004004,0x00000204,
		0x00004000,0x00000200,0x01000000,0x01004004,
		0x01000204,0x00004204,0x00004200,0x00000000,
		0x00000200,0x01000004,0x00000004,0x01000200,
		0x00000000,0x01000204,0x01000200,0x00004200,
		0x00000204,0x00004000,0x01004204,0x01000000,
		0x01004200,0x00000004,0x00004004,0x01004204,
		0x01000004,0x01004200,0x01004000,0x00004004,
	],
	[
		u32(0x20800080),0x20820000,0x00020080,0x00000000,
		0x20020000,0x00800080,0x20800000,0x20820080,
		0x00000080,0x20000000,0x00820000,0x00020080,
		0x00820080,0x20020080,0x20000080,0x20800000,
		0x00020000,0x00820080,0x00800080,0x20020000,
		0x20820080,0x20000080,0x00000000,0x00820000,
		0x20000000,0x00800000,0x20020080,0x20800080,
		0x00800000,0x00020000,0x20820000,0x00000080,
		0x00800000,0x00020000,0x20000080,0x20820080,
		0x00020080,0x20000000,0x00000000,0x00820000,
		0x20800080,0x20020080,0x20020000,0x00800080,
		0x20820000,0x00000080,0x00800080,0x20020000,
		0x20820080,0x00800000,0x20800000,0x20000080,
		0x00820000,0x00020080,0x20020080,0x20800000,
		0x00000080,0x20820000,0x00820080,0x00000000,
		0x20000000,0x20800080,0x00020000,0x00820080,
	]
]

pub fn (mut des XADStuffItDESHandle) init_with_handle(fh os.File, pos u32) {
	des.fh = fh
	des.streampos = pos
	des.a = bytes.uint_32_be(des.key, 0)
	des.b = bytes.uint_32_be(des.key, 4)
	des.c = bytes.uint_32_be(des.key, 8)
	des.d = bytes.uint_32_be(des.key, 12)
}

// This produces decryted u32 (8 bytes) based on the current state of the handle (previous opterations influence this)
// pos is the position in the file (this has to be after the pos before/init)
pub fn (mut des XADStuffItDESHandle) produce_block_at_offset(pos u32) u32 {
	// Original code didn't use pos!!! 

	if mut fh := des.fh {

		if pos < des.streampos {
			panic('cannot go backwards, pos `${pos}` must be equal or greater than previous `${des.streampos}`')
		}

		// jump to pos
		fh.seek(i64(pos), .start) or { panic('${err}') }

		// check if in file!
		if fh.eof() {
			panic('At EOF!!')
		}

		if des.block.len != 8 {
			panic('block length is NOT 8!')
		} 

		fh.read_bytes_into(pos, mut des.block) or { panic('${err}') }
		des.streampos = pos + 8

		left 	:= 	bytes.uint_32_be(des.block, 0)  // left=CSUInt32BE(&block[0]);
		right 	:= 	bytes.uint_32_be(des.block, 4)
		l := left^des.a^des.c
		r := right^des.b^des.d

		bytes.set_uint_32_be(mut des.block, 0, l)
		bytes.set_uint_32_be(mut des.block, 4, r)

		des.c = des.d
		des.d = rotate_right(left^right^des.a^des.b^des.d, 1)
		//println('des.block: ${des.block} ${l} ${r}')

		return 8 // why?!? _blocklength if successful returns that read 8 bytes
	} else {
		panic('No file handle!?!')
	}
	return 0
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

@[inline]
fn nibble(key []u8, n int) u32 {
	if key.len != 8 {
		panic('key is NOT []int{len: 8}!')
	}
	return u32( u32(key[(n & 0x0f) >> 1] >> (u32((n ^ 1) & 1) << 2)) & 0x0f)
} 

// Takes mut []int len 8
// was, StuffItDESSetKey
fn stuffit_des_setkey(key []u8,
					  mut ks &StuffItDESKeySchedule) {
	if key.len != 8 {
		panic('key NOT []int{len: 8}!')
	}

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

@[inline]
fn encrypt(mut left &u32, right u32, subkey []u32) {
	// check subkey len!
	if subkey.len != 2 {
		println('Excepting len 2 for subkey!')
	}
	u := u32(right ^ subkey[0])
	t := rotate_right(right, 4) ^ subkey[1]

	left ^=	des_sptrans[0][(u>>2)&0x3f] ^
			des_sptrans[2][(u>>10)&0x3f] ^
			des_sptrans[4][(u>>18)&0x3f] ^
			des_sptrans[6][(u>>26)&0x3f] ^
			des_sptrans[1][(t>>2)&0x3f] ^
			des_sptrans[3][(t>>10)&0x3f] ^
			des_sptrans[5][(t>>18)&0x3f] ^
			des_sptrans[7][(t>>26)&0x3f]
}	

// called by key_for_password_data
fn stuffit_des_crypt(mut data []u8, ks &StuffItDESKeySchedule, enc bool) {
	if data.len != 8 {
		panic('key NOT []int{len: 8}!')
	}

	mut left 	:= reverse_bits(bytes.uint_32_be(data, 0))
	mut right 	:= reverse_bits(bytes.uint_32_be(data, 4))

	left 	= rotate_right(left, 29)
	right	= rotate_right(right, 29)

	if enc {
		for i :=0; i < 16; i += 2 {
			encrypt(mut left, right, ks.subkeys[i]) // was, Encrypt(&left,right,ks->subkeys[i]);
			encrypt(mut right, left, ks.subkeys[i + 1])
		}
	} else {
		for i := 15; i > 0; i -=2 {
			encrypt(mut left, right, ks.subkeys[i])
			encrypt(mut right, left, ks.subkeys[i - 1])
		}
	}

	left 	= rotate_right(left, 3)
	right	= rotate_right(right, 3)

	bytes.set_uint_32_be(mut data, 0, reverse_bits(right))
	bytes.set_uint_32_be(mut data, 4, reverse_bits(left))
}

// Calculate archive key and IV from password and mkey
pub fn key_for_password_data(password string, entrykey []u8, mkey ?[]u8) ?XADStuffItDESHandle {

	if mk := mkey { // not none, XADStuffitParser ONLY calls this if not none, see decryptHandleForEntryWithDictionary
		if mk.len != 8 {
			// Depends on len 8 below
			panic("mkey is NOT length 8!")
		} else {
			// Weirdly not checked in orignal
			if entrykey.len < 16 {
				panic("entrykey length less than 16 (${entrykey.len})!")
			}

			mut ks:= &StuffItDESKeySchedule{subkeys: [][]u32{len: 16, init: []u32{len: 2}}}

			// Is ther a better way?
			mut passblock := [u8(0),0,0,0,0,0,0,0]
			mut length := password.len
			if password.len > 8 {
				length = 8
			}
			for i in 0 .. length {
				passblock[i] = password[i]
			}

			// Calculate archive key and IV from password and mkey
			mut archivekey := []u8{len: 8}
			mut archiveiv  := []u8{len: 8}

			initialkey := [u8(0x01), 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
			for i := 0; i < 8; i++ {
				archivekey[i] = initialkey[i]^(passblock[i]&0x7F)
			}

			stuffit_des_setkey(initialkey, mut &ks)
			stuffit_des_crypt(mut archivekey, ks, true)

			// copy mk into achiveiv
			for i := 0; i < 8; i++ {
				archiveiv[i] = mk[i]
			}
			stuffit_des_setkey(archivekey, mut &ks)
			stuffit_des_crypt(mut archiveiv, ks, false)

			// Verify the password.
			mut verifyblock := [u8(0),0,0,0,0,0,0,4]
			for i := 0; i < 4; i++ {
				verifyblock[i] = archiveiv[i]  // only the first 4 will match
			}
			
			stuffit_des_setkey(archivekey, mut ks)
			stuffit_des_crypt(mut verifyblock, ks, true)
			if verifyblock[4 .. ] != archiveiv[4 .. ] {
				// println('${verifyblock} ${archiveiv}')
				return none
			}

			// Calculate file key and IV from entrykey, archive key and IV.
			mut filekey := entrykey[ .. 8].clone()
			mut fileiv := entrykey[8 .. 16].clone()
			//unsafe { vmemcpy(&filekey.addr[0], &entrykey.addr[0], 8) }
			//unsafe { vmemcpy(&fileiv,&entrykey[8:].addr[0], 8) }

			stuffit_des_setkey(archivekey, mut ks)
			stuffit_des_crypt(mut filekey, ks, false)
			for i := 0; i < 8; i++ {
				filekey[i] ^= archiveiv[i]
			}
			stuffit_des_setkey(filekey, mut &ks)
			stuffit_des_crypt(mut fileiv, ks, false)

			mut key := filekey[ .. 8].clone()
			key << fileiv[ .. 8]
			
			return XADStuffItDESHandle {
				key:	key.clone()
				block: 	[]u8{len: 8}
				ks:		ks
			}
		}
	} else {
		panic("mkey is not set!")
	}
}
