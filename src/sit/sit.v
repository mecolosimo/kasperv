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
const sitfh_fname						= 3		 // SITFH_FNAME, xadUINT8 31 byte filename
const sitfh_rsrclength 					= 84 	 // xadUINT32 decompressed rsrc length
const sitfh_datalength					= 88  	 // xadUINT32 decompressed data length
const sitfh_comprlength 				= 92  	 // xadUINT32 compressed rsrc length
const sitfh_compdlength					= 96 	 // xadUINT32 compressed data length

struct SitFile {
pub:
	name				string	@[xdoc: 'name of file']
	rsrclength			u32 	@[xdoc: 'rsrc uncompressed length']
	datalength			u32 	@[xdoc: 'data uncompressed length']

	rsrc_comp_length	u32 	@[xdoc: 'rsrc compressed length']
	data_comp_length	u32 	@[xdoc: 'data compressed length']

	start				i64		@[xdoc: 'staring location in file']
}

struct SitFolder {
pub:
	files []SitFile
}

struct Sit {
pub:
	entrykey				?string
	is_stuffit_encrypted	bool
	totalsize				u32
	folders					[]SitFolder
}

// try to parse a SIT! file and return info
pub fn parse(mut f os.File) !Sit {
	mut entrykey := ?string(none)
	mut is_stuffit_encrypted := false
	mut header := []u8{len: sit_filehdrsize, cap: sit_filehdrsize, init: 0}
	mut folders := []SitFolder{}
	mut files := []SitFile{}	// Not trying to keep the hierarchy (much harder and we don't care yet)

	// This is wrong! This is **NOT** the numfiles!
	numfiles := bytes.read_uint_16_be_at(f, u64(f.tell() or { panic('${err}')})) or { panic('${err}') } 
	mut sit_numfiles := int(0) // found files

	base := f.tell() or { panic('${err}') }
	
	// seems to be total size of sit: minus base
	totalsize := bytes.read_uint_32_be_at(f, (sizeof(u8))*6) or { panic('${err}') } 
	
	// jump over stuff
	f.seek(i64(sizeof(u8))*22, .start) or { panic('${err}') }

	for {
		offset_in_file := f.tell() or { panic('${err}') }
		if offset_in_file+sit_filehdrsize > totalsize+base {
			// done like loop
			break
		}
		
		// Read header
		f.read_bytes_into(u64(f.tell() or { panic('${err}') }), 
			mut header) or { panic('${err}') }

		if bytes.uint_16_be(header, sitfh_hdrcrc) == crc.xad_calculate_crc(0, header, 110, crc.xad_crc_table_a001) {
			// header CRC okay
			rsrclength := bytes.uint_32_be(header, sitfh_rsrclength)	// was resourcelength
			rsrcmethod := header[sitfh_rsrcmethod] 						// was resourcemethod
			rsrccomplen := bytes.uint_32_be(header, sitfh_comprlength) 	// was resourcecomplen, 
			datacomplen := bytes.uint_32_be(header, sitfh_compdlength) 	// uncompressed data length
			datalength := bytes.uint_32_be(header, sitfh_datalength)
			datamethod := header[sitfh_datamethod]
			
			namelen := if header[sitfh_namelen] > 31 { 31 } else { header[sitfh_namelen] }
			name := header[sitfh_fname .. namelen].bytestr()

			start := f.tell() or { panic('${err}') }

			if datamethod&stuffit_folder_mask == stuffit_start_folder ||
				rsrcmethod&stuffit_folder_mask == stuffit_start_folder
			{
				println("StuffItStartFolder: ${name}")
				println("${header}")
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
				// creat/add folder
				folders <<
					SitFolder {
						files: 	files
					}
				println("StuffItEndFolder: ${files.len}")
				sit_numfiles = sit_numfiles + files.len
				files.clear()
			} else {
				files << SitFile {
					name:				name

					rsrclength:			rsrclength
					datalength:			datalength

					rsrc_comp_length:	rsrccomplen
					data_comp_length:	datacomplen

					start:				start
				}
				//println("File: ${files#[-1..]}")
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

		if is_stuffit_encrypted && entrykey != none { 
			// work around for https://github.com/vlang/v/issues/22936
			if skey := entrykey {
				if skey.len > 0 { 
					panic("Not encrypted but got entrykey (${entrykey})!")
				}
			}
		}

	}	// end bare for (while)

	if is_stuffit_encrypted && entrykey == none {
		println("Encryted but did not set entrykey")
	}

	// Check sit
	mut total_found_files := 0
	for folder in folders {
		total_found_files = total_found_files + folder.files.len
	}
	if numfiles != total_found_files {
		println("SIT should have ${numfiles}, but found ${total_found_files}")
	}

	return Sit{
		entrykey: 				entrykey
		is_stuffit_encrypted:	is_stuffit_encrypted
		totalsize:				totalsize
		folders:				folders
	}
}