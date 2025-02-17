// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
// Based on Unarchiver/XADMaster/CRC.m
module crc

pub fn xad_calculate_crc(prev_crc u32, buffer []u8, length int, table []u32) u32 {
	// was crc.m:XADCalculateCRC
	mut crc_val := prev_crc
	for i := 0; i < length; i++ {
		crc_val = xad_crc(crc_val, buffer[i], table)
	}
	return crc_val
}

fn xad_crc(prev_crc u32, b u8, table []u32) u32 {
	return table[ u32(prev_crc ^ b) & 0xff ]^u32( prev_crc >> 8 )
}
