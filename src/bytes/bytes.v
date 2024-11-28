
// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module bytes

import os

// Silly this isn't built in, read a 32 bit int in big endian order at given `position`
pub fn read_uint_32_be_at(f os.File, position u64) !u32 {
	bytes := f.read_bytes_at(4, position)
	result := ( u32(bytes[0]) << 24 ) | ( u32(bytes[1]) << 16) | ( u32(bytes[2]) << 8) | ( u32(bytes[3]) )
	return result
}

// Read little endian order at given `position`
pub fn read_uint_32_le_at(f os.File, position u64) !u32 {
	bytes := f.read_bytes_at(4, position)
	result := ( u32(bytes[3]) << 24 ) | ( u32(bytes[2]) << 16) | ( u32(bytes[1]) << 8) | ( u32(bytes[0]) )
	return result
}

// Read a 16 bit int in big endian order at given `position`
pub fn read_uint_16_be_at(f os.File, position u64) !u32 {
	bytes := f.read_bytes_at(2, position)
	result := u32( u32(bytes[0]) << 8 ) | ( u32(bytes[1]) )
	return result
}

// read a 32 bit int in big endian order at current position
pub fn read_uint_32_be(f os.File ) !u32 {
	return read_uint_32_be_at(f, u64(f.tell() or { panic('${err}') }) + 1)
}

// read a 32 bit int in little endian order at current position
pub fn read_uint_32_le(f os.File ) !u32 {
	return read_uint_32_le_at(f, u64(f.tell() or { panic('${err}') }) + 1)
}

// read a 16 bit int in big endian order from buffer of u8 bytes
pub fn uint_16_be(buffer []u8, index int) u16 {
	return ( u16(buffer[index]) << 8) | ( u16(buffer[index + 1]) )
}

// read a 32 bit int in big endian order from buffer of u8 bytes
pub fn uint_32_be(buffer []u8, index int) u32 {
	return ( u32(buffer[index]) << 24 ) | ( u32(buffer[index +1]) << 16) | ( u32(buffer[index + 2]) << 8) | ( u32(buffer[index + 3]) )
}

pub fn uint_32_le(buffer []u8, index int) u32 {
	return ( u32(buffer[index + 3]) << 24 ) | ( u32(buffer[index + 2]) << 16) | ( u32(buffer[index + 1]) << 8) | ( u32(buffer[index]) )
}