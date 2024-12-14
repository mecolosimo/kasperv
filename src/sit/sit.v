// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
// Derived from Unarchiver/XADMaster/XADStuffitParser.m
module sit

import os
import crc
import bytes

const stuffit_encrypted_flag = 0x80 // password protected bit
const stuffit_folder_contains_encrypted = 0x10 // folder contains encrypted items bit
const stuffit_start_folder = 0x20 // start of folder
const stuffit_end_folder = 0x21 // end of folder
const stuffit_folder_mask = (~(stuffit_encrypted_flag | stuffit_folder_contains_encrypted))
const sitfh_hdrcrc = 110 // xadUINT16 crc of file header
const sitfh_filedhrsize = 112
const sitfh_rsrcmethod = 0 // SITFH_COMPRMETHOD, xadUINT8 rsrc fork compression method
const sitfh_datamethod = 1 // SITFH_COMPDMETHOD, xadUINT8 data fork compression method
const sitfh_namelen = 2
const sitfh_fname = 3 // SITFH_FNAME, xadUINT8 31 byte filename
const sitfh_numfiles = 48
const sitfh_parentoffset = 58 // xadUINT32 offset of parent entry */
const sitfh_rsrclength = 84 // xadUINT32 decompressed rsrc length
const sitfh_datalength = 88 // xadUINT32 decompressed data length
const sitfh_comprlength = 92 // xadUINT32 compressed rsrc length
const sitfh_compdlength = 96 // xadUINT32 compressed data length

struct SitFile {
pub:
	name       string @[xdoc: 'name of file']
	rsrclength u32    @[xdoc: 'rsrc uncompressed length']
	datalength u32    @[xdoc: 'data uncompressed length']

	rsrc_comp_length u32 @[xdoc: 'rsrc compressed length']
	data_comp_length u32 @[xdoc: 'data compressed length']

	start i64 @[xdoc: 'staring location in file']
}

struct SitFolder {
pub:
	name     string      @[xdoc: 'name of folder']
	files    []SitFile   @[xdoc: 'Files']
	folders  []SitFolder @[xdoc: 'Folders']
	numfiles u16         @[xdoc: 'SIT number of files and folders']
	offset   u32         @[xdoc: 'Offset (bytes) of header in file']
	parent   u32         @[xdoc: 'Offset of parent\'s header in file']
}

struct Sit {
pub:
	entrykey             ?string
	is_stuffit_encrypted bool
	totalsize            u32
	folders              []SitFolder
}

// Returns count of files under directory
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
			println('\tExpecting ${folder.numfiles} found ${nfs} under ${folder.name}')
			rst = false
		} else {
			println('\tFolder ${folder.name} looks fine')
		}
	}
	return rst
}

// try to parse a SIT! file and return info
pub fn parse(mut f os.File) !Sit {
	mut entrykey := ?string(none)
	mut offset := []u32{len: 0xFF} // see https://github.com/vlang/v/issues/23089
	mut is_stuffit_encrypted := false
	mut header := []u8{len: sitfh_filedhrsize, cap: sitfh_filedhrsize, init: 0}
	// Doing a Depth-First Seach (DFS), I think this is what the SIT is.
	mut depth := u8(0)
	mut root := ?SitFolder(none) // Top level folder
	mut folders := [][]SitFolder{} // Folders are "special" files
	mut folders_map := map[u32]SitFolder{}
	mut files := [][]SitFile{}

	// This is wrong! This is **NOT** the numfiles!
	// numfiles := bytes.read_uint_16_be_at(f, u64(f.tell() or { panic('${err}')})) or { panic('${err}') }

	mut sit_folder_name := []string{len: 0xFF} // don't want to make fields in struct pub & mut
	mut numfiles := []u16{len: 0xFF}

	base := f.tell() or { panic('${err}') }

	// seems to be total size of sit: minus base
	totalsize := bytes.read_uint_32_be_at(f, (sizeof(u8)) * 6) or { panic('${err}') }

	// jump over stuff
	f.seek(i64(sizeof(u8)) * 22, .start) or { panic('${err}') }

	for {
		offset_in_file := f.tell() or { panic('${err}') }
		if offset_in_file + sitfh_filedhrsize > totalsize + base {
			// done like loop
			break
		}

		// Read header
		f.read_bytes_into(u64(f.tell() or { panic('${err}') }), mut header) or { panic('${err}') }

		if bytes.uint_16_be(header, sitfh_hdrcrc) == crc.xad_calculate_crc(0, header,
			110, crc.xad_crc_table_a001) {
			// header CRC okay
			rsrclength := bytes.uint_32_be(header, sitfh_rsrclength) // was resourcelength
			rsrcmethod := header[sitfh_rsrcmethod] // was resourcemethod
			rsrccomplen := bytes.uint_32_be(header, sitfh_comprlength) // was resourcecomplen,
			datacomplen := bytes.uint_32_be(header, sitfh_compdlength) // uncompressed data length
			datalength := bytes.uint_32_be(header, sitfh_datalength)
			datamethod := header[sitfh_datamethod]
			mut parent_offset := u32(0)
			namelen := if header[sitfh_namelen] > 31 { 31 } else { header[sitfh_namelen] }
			name := header[sitfh_fname..sitfh_fname + namelen].bytestr()

			start := f.tell() or { panic('${err}') }

			if datamethod & stuffit_folder_mask == stuffit_start_folder
				|| rsrcmethod & stuffit_folder_mask == stuffit_start_folder {
				println('StuffItStartFolder ${name}')
				if datamethod & stuffit_folder_mask != 0 || rsrcmethod & stuffit_folder_mask != 0 {
					println('\tEncrypted data')
					is_stuffit_encrypted = true
				} else {
					panic('\tSIT not encrypted!')
					is_stuffit_encrypted = false
				}

				offset[depth] = u32(offset_in_file) // was i64offset[depth] = u32(offset_in_file) // was i64

				depth = depth + 1
				// numfiles[depth] = bytes.uint_16_be(header, sitfh_numfiles)
				files << []SitFile{}

				// sit_folder_name[depth] = name
				numfiles << bytes.uint_16_be(header, sitfh_numfiles) // num total files under directory
				sit_folder_name << name

				parent_offset = bytes.uint_32_be(header, sitfh_parentoffset) + u32(base)

				// in the code
				f.seek(i64(sizeof(u8)) * start, .start) or { panic('${err}') }
			} else if datamethod & stuffit_folder_mask == stuffit_end_folder
				|| rsrcmethod & stuffit_folder_mask == stuffit_end_folder {
				// creat/add
				println('StuffItEndFolder: ${sit_folder_name[sit_folder_name.len - 1]} ${files.len} ${depth}')
				println('\tLen folder: ${folders.len}')
				if offset[depth - 1] != 0 {
					sf := SitFolder{
						name:     sit_folder_name.pop()
						files:    if files.len > 0 { files.pop() } else { []SitFile{} }
						folders:  if folders.len > 0 { folders } else { []SitFolder{} }
						numfiles: numfiles.pop()
						offset:   offset[depth - 1]
						parent:   parent_offset
					}

					println('\tFolder name ${sf.name}')
					println('\tNumber files: ${sf.numfiles}')
					println('\t\tFound files: ${sf.files.len}')
					println('\tNumber folders: ${sf.folders.len}')

					folders_map[offset[depth - 1]] = sf
					if depth == 1 {
						if root == none {
							println('root: ${sf.folders}')
							root = sf
						} else {
							panic('Root is already set!')
						}
					} else if folders.len > 0 {
						folders[folders.len - 1] << sf
					} else {
						// empty folder list?!?
						println('\tFolder list empty')
						// folders << [ sf ]
						// folders_map[offset[depth - 1]].folders << sf
					}

					// offset[depth - 1] = 0
				} else {
					panic('offset not set for depth ${depth - 1}!')
				}

				depth = depth - 1
			} else {
				println('Adding file: ${name} ${files.len} at ${depth}')
				// File
				files[files.len - 1] << SitFile{
					name: name

					rsrclength: rsrclength
					datalength: datalength

					rsrc_comp_length: rsrccomplen
					data_comp_length: datacomplen

					start: start
				}
				// println("File: ${files#[-1..]}")
				mut entrykey_array := []u8{len: 16, cap: 16, init: 0}
				if rsrclength != 0 {
					if rsrcmethod & stuffit_encrypted_flag != 0 {
						// encrypted get entrykey
						entrykey_array.clear()
						f.read_from(u64(i64(sizeof(u8)) * start + rsrccomplen - 16), mut
							entrykey_array) or { panic('${err}') }
						entrykey = entrykey_array.bytestr()
					}
				}

				if datalength != 0 && rsrclength == 0 {
					if datamethod & stuffit_encrypted_flag != 0 {
						if datacomplen < 16 {
							panic('Illegal Data')
						}
						// encrypted get entrykey
						entrykey_array.clear()
						f.read_from(u64(i64(sizeof(u8)) * start + rsrccomplen - 16), mut
							entrykey_array) or { panic('${err}') }
						entrykey = entrykey_array.bytestr()
					}
				}

				// TODO: if datalength == 0 && rsrclength == 0

				f.seek(u64(sizeof(u8)) * start + datacomplen + rsrccomplen, .start) or {
					panic('${err}')
				}
			}
		} else {
			panic('Bad CRC')
		}

		if is_stuffit_encrypted && entrykey != none {
			// see if you have issuses: https://github.com/vlang/v/issues/22936
			if entrykey.len > 0 {
				panic('Not encrypted but got entrykey (${entrykey})!')
			}
		}
	} // end bare for (while)

	if is_stuffit_encrypted && entrykey == none {
		println('Encryted but did not set entrykey')
	}

	// println(folders)
	// Quick checking of sit
	if root != none {
		// have something
		if !check_sit(root.folders) {
			panic('Bad SIT')
		}
	} else {
		panic('No root folder!')
	}

	return Sit{
		entrykey:             entrykey
		is_stuffit_encrypted: is_stuffit_encrypted
		totalsize:            totalsize
		folders:              folders[0] // [0]
	}
}
