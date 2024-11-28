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
const sitfh_numfiles					= 48
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
	name				string			@[xdoc: 'name of folder']
	files 				[]SitFile		@[xdoc: 'Files']
	folders				[]SitFolder		@[xdoc: 'Folders']
	numfiles			u16				@[xdoc: 'SIT number of files and folders']
}

struct Sit {
pub:
	entrykey				?string
	is_stuffit_encrypted	bool
	totalsize				u32
	folders					[]SitFolder
}

fn count_files(folder SitFolder) int {
	mut cnt := folder.files.len
	for f in folder.folders {
		cnt = cnt + count_files(f)
	}
	return cnt
}

// quick sit check
fn check_sit(folders []SitFolder) bool {
	mut rst := true
	for folder in folders {
		if folder.folders.len > 0 {
			if !check_sit(folder.folders) {
				rst = false
			}
		}
		nfs := count_files(folder)
		if folder.numfiles != nfs {
			println("\tExpecting ${folder.numfiles} found ${nfs} under ${folder.name}")
			rst = false
		} else {
			println("\tFoler ${folder.name} looks fine")
		}
	}
	return rst
}

// try to parse a SIT! file and return info
pub fn parse(mut f os.File) !Sit {
	mut entrykey := ?string(none)
	mut is_stuffit_encrypted := false
	mut header := []u8{len: sit_filehdrsize, cap: sit_filehdrsize, init: 0}
	// Doing a Depth-First Seach (DFS), I think this is what the SIT is.
	mut depth := u8(0)
	mut folders := [][]SitFolder{len: 0xFF}	// Folders are "special" files
	mut files := [][]SitFile{len: 0xFF}		// Trying to keep the hierarchy

	// This is wrong! This is **NOT** the numfiles!
	// numfiles := bytes.read_uint_16_be_at(f, u64(f.tell() or { panic('${err}')})) or { panic('${err}') } 
	mut sit_folder_name := []string{len: 0xFF}	// don't want to make fields in struct pub & mut
	mut numfiles :=	[]u16{len: 0xFF}

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
				println("StuffItStartFolder")
				if datamethod&stuffit_folder_mask != 0 ||
					rsrcmethod&stuffit_folder_mask != 0 {
					println("\tEncrypted data")
					is_stuffit_encrypted = true
				} else {
					panic("\tSIT not encrypted!")
					is_stuffit_encrypted = false
				}

				depth = depth + 1
				numfiles[depth] = bytes.uint_16_be(header, sitfh_numfiles)	// includes folders :(
				sit_folder_name[depth] = name

				// in the code
				f.seek(i64(sizeof(u8))*start, .start) or { panic('${err}') }

			} else if datamethod&stuffit_folder_mask == stuffit_end_folder ||
						rsrcmethod&stuffit_folder_mask == stuffit_end_folder {
				// creat/add
				sf := SitFolder {
						name:		sit_folder_name[depth]
						files: 		if files.len > 0 { files[depth] } else { []SitFile{} }
						folders:	if folders.len > 0 { folders[depth] } else { []SitFolder{} }
						numfiles:	numfiles[depth]
					}
				folders[depth - 1] << sf
				println("StuffItEndFolder: ${files.len} ${sf.name} ${depth}")
				println("\tFolder name ${sf.name}")
				println("\tNumber files: ${sf.numfiles}")
				println("\t\tFound files: ${sf.files.len}")
				sit_folder_name[depth] = ""
				if files.len >= depth { files[depth].clear() }
				if folders.len >= depth { folders[depth].clear() }
			
				depth = depth - 1
			} else {
				// File
				files[depth] << SitFile {
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

	// Quick checking of sit
	if folders[0].len > 0 {
		//have something
		if !check_sit(folders[0]) {
			panic("Bad SIT")
		}
	} else {
		println("Folders: ${folders}")
	}

	return Sit{
		entrykey: 				entrykey
		is_stuffit_encrypted:	is_stuffit_encrypted
		totalsize:				totalsize
		folders:				folders[0]
	}
}