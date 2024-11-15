// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
// Derived from Unarchiver/XADMaster/XADStuffitParser.m
module sit

import os

import crc
import bytes

const stuffit_encrypted_flag			= 0x80	 // password protected bit
const stuffit_folder_contains_encrypted	= 0x10	 // folder contains encrypted items bit
const stuffit_start_folder				= 0x20	 // start of folder
const stuffit_end_folder				= 0x21	 // end of folder
const stuffit_folder_mask				= (~(stuffit_encrypted_flag|stuffit_folder_contains_encrypted))
const sitfh_hdrcrc 						= 110	 // xadUINT16 crc of file header
const sit_filehdrsize 					= 112
const sitfh_rsrcmethod					= 0		 // SITFH_COMPRMETHOD, xadUINT8 rsrc fork compression method
const sitfh_datamethod					= 1		 // SITFH_COMPDMETHOD, xadUINT8 data fork compression method 
const sitfh_namelen						= 2
const sitfh_rsrclength 					= 84 	 // xadUINT32 decompressed rsrc length
const sitfh_datalength					= 88  	 // xadUINT32 decompressed data length
const sitfh_comprlength 				= 92  	 // xadUINT32 compressed rsrc length
const sitfh_compdlength					= 96 	 // xadUINT32 compressed data length

struct Sit {
pub:
	entrykey				string
	is_stuffit_encrypted	bool
	totalsize				u32
}

// try to parse a SIT! file and return info
pub fn parse(mut f os.File) !Sit {
	mut entrykey := ""
	mut is_stuffit_encrypted := false
	mut header := []u8{len: sit_filehdrsize, cap: sit_filehdrsize, init: 0}

	// numfiles := 
	base := f.tell() or { panic('${err}') }

	totalsize := bytes.read_uint_32_be_at(f, (sizeof(u8))*6) or { panic('${err}') } 
	
	// jump over stuff
	f.seek(i64(sizeof(u8))*12, .current) or { panic('${err}') }

	for {
		offset_in_file := f.tell() or { panic('${err}') }
		if offset_in_file+sit_filehdrsize > totalsize+base {
			// done
			break
		}
		
		// Read header
		f.read_bytes_into(u64(f.tell() or { panic('${err}') }), 
			mut header) or { panic('${err}') }

		if bytes.uint_16_be(header, sitfh_hdrcrc) == crc.xad_calculate_crc(0, header, 110, crc.xad_crc_table_a001) {
			// header CRC okay
			rsrclength := bytes.uint_32_be(header, sitfh_rsrclength)	// was resourcelength
			rsrcmethod := header[sitfh_rsrcmethod] 						// was resourcemethod
			rsrccomplen := bytes.uint_32_be(header, sitfh_comprlength) 	// was resourcecomplen
			datacomplen := bytes.uint_32_be(header, sitfh_compdlength) 	// uncompressed data length
			datalength := bytes.uint_32_be(header, sitfh_datalength)
			datamethod := header[sitfh_datamethod]

			namelen := if header[sitfh_namelen] > 31 { 31 } else { header[sitfh_namelen] }

			start := f.tell() or { panic('${err}') }

			println("namelen: ${namelen}")
			println("start: ${start}")
			println("datacomplen ${datacomplen}")

			if datamethod&stuffit_folder_mask == stuffit_start_folder ||
				rsrcmethod&stuffit_folder_mask == stuffit_start_folder
			{
				println("StuffItStartFolder!")
				if datamethod&stuffit_folder_mask != 0 ||
					rsrcmethod&stuffit_folder_mask != 0 {
					println("Encrypted data")
					is_stuffit_encrypted = true
				} else {
					panic("SIT not encrypted!")
					is_stuffit_encrypted = false
				}

				// in the code
				f.seek(i64(sizeof(u8))*start, .start) or { panic('${err}') }
			} else if datamethod&stuffit_folder_mask == stuffit_end_folder ||
						rsrcmethod&stuffit_folder_mask == stuffit_end_folder {
				println("StuffItEndFolder!")
			} else {
				mut entrykey_array :=  []u8{len: 16, cap: 16, init: 0}
				if rsrclength != 0 {
					if rsrcmethod&stuffit_encrypted_flag != 0 {
						// encrypted get entrykey
						entrykey_array.clear()
						f.read_from(u64(i64(sizeof(u8))*start+rsrccomplen-16), mut entrykey_array) or { panic('${err}') }
						entrykey = entrykey_array.bytestr()
					}
				}

				if datalength != 0 && rsrclength == 0 {
					if datamethod&stuffit_encrypted_flag != 0 {
						if datacomplen < 16 {
							panic("Illegal Data")
						}
						// encrypted get entrykey
						entrykey_array.clear()
						f.read_from(u64(i64(sizeof(u8))*start+rsrccomplen-16), mut entrykey_array) or { panic('${err}') }
						entrykey = entrykey_array.bytestr()
					}
				}

				// TODO: if datalength == 0 && rsrclength == 0

				f.seek(u64(sizeof(u8))*start+datacomplen+rsrccomplen, .start) or { panic('${err}') }
			} 
		} else {
			panic("Bad CRC")
		}

		if is_stuffit_encrypted && entrykey.len > 0 {
			panic("Not encrypted but got entrykey!")
		}
	}	// end bare for (while)

	return Sit{
		entrykey: 				entrykey
		is_stuffit_encrypted:	is_stuffit_encrypted
		totalsize:				totalsize
	}	
}