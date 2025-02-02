// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
// Derived from Unarchiver/XADMaster/XADStuffitParser.m
module sit

import crc
import os

// our stuff
import bytes
import utils

const stuffit_encrypted_flag = 0x80 	// password protected bit
const stuffit_folder_contains_encrypted = 0x10 // folder contains encrypted items bit
const stuffit_method_mask = ~stuffit_encrypted_flag & 0x0f // used to determine encyption, added 0x0f
const stuffit_start_folder = 0x20 	// start of folder
const stuffit_end_folder = 0x21 	// end of folder
const stuffit_folder_mask = (~(stuffit_encrypted_flag | stuffit_folder_contains_encrypted))
const stuffit_numfile = 0x04 		// number of files and direcorties at root

// Consts for stuffit header
const sitfh_hdrcrc = 110 		// xadUINT16 crc of file header
const sitfh_filedhrsize = 112	// 0x70
const sitfh_rsrcmethod = 0 		// SITFH_COMPRMETHOD, xadUINT8 rsrc fork compression method
const sitfh_datamethod = 1 		// SITFH_COMPDMETHOD, xadUINT8 data fork compression method
const sitfh_namelen = 2
const sitfh_fname = 3 			// SITFH_FNAME, xadUINT8 31 byte filename
const sitfh_numfiles = 48 		// was 48 le, now be

const sitfh_parentoffset = 58 	// xadUINT32 offset of parent entry
const sitfh_rsrclength = 84 	// xadUINT32 decompressed rsrc length
const sitfh_datalength = 88 	// xadUINT32 decompressed data length
const sitfh_comprlength = 92 	// xadUINT32 compressed rsrc length
const sitfh_compdlength = 96	// xadUINT32 compressed data length
const sitfh_rsrcpad = 104 		// xadUINT8 rsrc padding bytes for encryption
const sitfh_datapad = 105 		// xadUINT8 data padding bytes for encryption

struct SitFile {
pub:
	name       		string 	@[xdoc: 'name of file']
	rsrclength 		u32    	@[xdoc: 'rsrc uncompressed length']
	rsrcpadding		u8		@[xdoc: 'rsrc padding bytes for encryption']
	datalength 		u32 	@[xdoc: 'data uncompressed length']
	datapadding		u8		@[xdoc: 'data padding bytes for encryption']

	rsrc_comp_length u32 	@[xdoc: 'rsrc compressed length']
	data_comp_length u32 	@[xdoc: 'data compressed length']

	start 			i64		@[xdoc: 'starting location in file']

	parent_folder 	?&SitFolder  @[xdox: 'parent folder, if any']
}

struct SitFolder {
pub:
	name          string @[xdoc: 'name of folder']
	numfiles      u16    @[xdoc: 'SIT number of files and folders']
	offset        u32    @[xdoc: 'Offset (bytes) of header in file']
	parent_offest u32    @[xdoc: 'Offset of parent\'s header in file']
	encrypted     bool   @[xdoc: 'Encrypted']
	datamethod    u8     @[xdoc: 'Data encryption method']
pub mut:
	files         []&SitFile   @[xdoc: 'Files']
	folders       []&SitFolder @[xdoc: 'Folders']
	parent_folder ?&SitFolder  @[xdox: 'Parent folder, if any']
}

// The file we are going to aptempt to find password
struct KasperFile {
	file	&SitFile
	comp 	[]u8	@[xdoc: 'Compressed data and rsrc fork']
	h		f64		@[xdoc: 'Shannon entropy of either data or rsrc fork']
}

struct Sit {
	f os.File					@[xdox: 'Open file handle']
pub:
	entrykey  ?[]u8
	totalsize u32
pub mut:
	files []&SitFile  			@[xdoc: 'Files']
	root  ?&SitFolder 			@[xdoc: 'Root Folder']
}

pub fn (f &SitFile) str() string {
	return '${f.name}\t${f.data_comp_length}\t${f.rsrc_comp_length}'
}

// quick sit check
fn check_sit(folders []&SitFolder) bool {
	mut rst := true
	for folder in folders {
		if folder.folders.len > 0 {
			if !check_sit(folder.folders) {
				rst = false
			}
		}
		nfs := folder.files.len + folder.folders.len
		if folder.numfiles != nfs {
			println('\tExpecting ${folder.numfiles} found ${nfs} files under ${folder.name}')
			rst = false
		} else {
			println('\tFolder ${folder.name} looks fine. Excepting ${nfs} files')
		}
	}
	return rst
}

fn check_sit_password_internal(passwd string, config SitConfig) !bool {
	s := config.sit or { dump(config); panic('No Sit!') }
	if ek := s.entrykey {
		mut des_handle := key_for_password_data(passwd, ek, config.mkey)
		if config.debug  {
			println("")
			dump(config)
			dump(des_handle)
		}
		if des_handle != none {
			println("Possible match: ${passwd}")
			return true
		} else {
			return false
		}
	} else {
		dump(config)
		panic('Need entrykey!')
	}
	return false
}

pub fn check_sit_password(config SitConfig) !bool {
	return replace_asterix(config, check_sit_password_internal)
}

fn find_kasper_file(root &SitFolder, fh &os.File) ?&KasperFile {
	mut kasper_file := ?&KasperFile(none)
	mut folder_queue := root.folders.clone()
	mut file_queue := []&SitFile{}
	mut folder_node := ?&SitFolder(none)
	mut folders_visited := []&SitFolder{}

	// Get all files using BFS (Folder then files)
	for {
		if folder_queue.len > 0 {
			folder_node = folder_queue.pop()
		} else {
			folder_node = none
		}

		if f := folder_node {
			if f !in folders_visited {
				folders_visited << f // folder

				// Enqueue unvisited folder
				for folder in f.folders {
					folder_queue << folder
				}

				// Enqueue unvisited filess
				for file in f.files {
					file_queue << file
				}
			}
		}

		// Have we reached the end?
		if folder_queue.len == 0 {
			break
		}
	}

	// If any have a "good" files
	file_queue.sort(a.datalength < b.datalength)

	if file_queue.len > 0 {
		data := fh.read_bytes_at(int(file_queue[0].data_comp_length + file_queue[0].rsrc_comp_length), u64(file_queue[0].start))
		kasper_file = &KasperFile {
			file: 	file_queue[0]
			comp: 	data
			h: 		utils.shannon(data)
		}
	} 
	return kasper_file
}

// Try to parse a SIT! file and return info
pub fn parse(mut f os.File) !Sit {
	mut entrykey := ?[]u8(none)
	mut is_stuffit_encrypted := false
	mut header := []u8{len: sitfh_filedhrsize, cap: sitfh_filedhrsize, init: 0}
	// Doing a Depth-First Seach (DFS), I think this is what the SIT is.
	mut root := ?&SitFolder(none)
	mut current_folder := ?&SitFolder(none) // Current folder, could be root

	// This is wrong! This is **NOT** the numfiles! See below.
	// numfiles := bytes.read_uint_16_be_at(f, u64(f.tell() or { panic('${err}')})) or { panic('${err}') }
	base := f.tell() or { panic('${err}') }

	// seems to be total size of sit: minus base
	totalsize := bytes.read_uint_32_be_at(f, (sizeof(u8)) * 6) or { panic('${err}') }

	root_numfiles := bytes.read_uint_16_be_at(f, stuffit_numfile) or { panic('${err}') } // num total files and folders in top level directory

	// jump over stuff
	f.seek(i64(sizeof(u8)) * 22, .start) or { panic('${err}') }

	for {
		offset_in_file := f.tell() or { panic('${err}') }
		if offset_in_file + sitfh_filedhrsize > totalsize + base {
			// done like loop
			break
		}

		if root == none {
			// Top level folder
			root = &SitFolder{
				name:     '<root>'
				numfiles: root_numfiles
				files:    []&SitFile{}
				folders:  []&SitFolder{}
				offset:   0
			}
			current_folder = root
		}

		// Read header
		f.read_bytes_into(u64(f.tell() or { panic('${err}') }), mut header) or { panic('${err}') }

		if bytes.uint_16_be(header, sitfh_hdrcrc) == crc.xad_calculate_crc(0, header,
			110, crc.xad_crc_table_a001) {
			// header CRC okay
			rsrclength := bytes.uint_32_be(header, sitfh_rsrclength) 	// was resourcelength
			rsrcmethod := header[sitfh_rsrcmethod] 						// was resourcemethod
			rsrccomplen := bytes.uint_32_be(header, sitfh_comprlength) 	// was resourcecomplen,
			datacomplen := bytes.uint_32_be(header, sitfh_compdlength) 	// uncompressed data length; AKA, XADDataLengthKey
			datalength := bytes.uint_32_be(header, sitfh_datalength)
			datamethod := header[sitfh_datamethod]
			datapadding := header[sitfh_datapad]						// AKA, StuffItBlockPadding
			rsrcpadding := header[sitfh_rsrcpad]						// AKA, StuffItBlockPadding
			namelen := if header[sitfh_namelen] > 31 { 31 } else { header[sitfh_namelen] }
			name := header[sitfh_fname..sitfh_fname + namelen].bytestr()

			start := f.tell() or { panic('${err}') }

			if datamethod & stuffit_folder_mask == stuffit_start_folder
				|| rsrcmethod & stuffit_folder_mask == stuffit_start_folder {
				//println('StuffItStartFolder: ${name}')
				if datamethod & stuffit_folder_mask != 0 || rsrcmethod & stuffit_folder_mask != 0 {
					//method := name_of_compression_method(datamethod & stuffit_method_mask)
					//println('\tEncrypted data: \n\t\tMethod: ${method}')
					is_stuffit_encrypted = true
				} else {
					//panic('\tSIT not encrypted!')
					is_stuffit_encrypted = false
				}
				mut sf := &SitFolder{
					name:          name
					encrypted:     is_stuffit_encrypted
					datamethod:    datamethod
					files:         []&SitFile{}
					folders:       []&SitFolder{}
					numfiles:      bytes.uint_16_be(header, sitfh_numfiles) // num total files under directory
					offset:        u32(offset_in_file) // was i64
					parent_offest: bytes.uint_32_be(header, sitfh_parentoffset) + u32(base)
					parent_folder: current_folder
				}
				if mut cf := current_folder {
					cf.folders << sf
					current_folder = sf
				} else {
					panic('Current folder is none!!')
				}

				// in the code
				f.seek(i64(sizeof(u8)) * start, .start) or { panic('${err}') }
			} else if datamethod & stuffit_folder_mask == stuffit_end_folder
				|| rsrcmethod & stuffit_folder_mask == stuffit_end_folder {
				// finish creating folder, end folder header
				if mut cf := current_folder {
					//println('StuffItEndFolder: ${name} to folder ${cf.name}')
					if mut pf := cf.parent_folder {
						current_folder = pf
					} else {
						current_folder = root
					}
				} else {
					panic('current_folder is none!')
				}

				// TODO: if datalength == 0 && rsrclength == 0
			} else {
				// File
				if mut cf := current_folder {
					//println('Adding file: ${name} to folder ${cf.name}')
					cf.files << &SitFile{
						name:       name
						rsrclength: rsrclength
						rsrcpadding: rsrcpadding
						datalength: datalength
						datapadding: datapadding

						rsrc_comp_length: rsrccomplen
						data_comp_length: datacomplen

						start: start

						parent_folder: current_folder
					}
				} else {
					panic('current_folder not set!')
				}

				//mut entrykey_array := []u8{len: 16, cap: 16, init: 0}
				if rsrclength != 0 {
					if rsrcmethod & stuffit_encrypted_flag != 0 {
						// encrypted get entrykey
						entrykey = f.read_bytes_at(16, u64(i64(sizeof(u8)) * start + rsrccomplen - 16))
						//println('Found entrykey: ${entrykey}')
					}
				}
			
				if datalength != 0 && rsrclength == 0 {
					if datamethod & stuffit_encrypted_flag != 0 {
						if datacomplen < 16 {
							panic('Illegal Data')
						}
						// encrypted get entrykey
						entrykey = f.read_bytes_at(16, u64(i64(sizeof(u8)) * start + rsrccomplen - 16))
						//println('Found entrykey: ${entrykey}')
					}
				}

				// position ourself to get next header
				f.seek(u64(sizeof(u8)) * start + datacomplen + rsrccomplen, .start) or {
					panic('${err}')
				}
			}
		} else {
			panic('Bad CRC: ${header} expecting ${bytes.uint_16_be(header, sitfh_hdrcrc)}')
		}

		if is_stuffit_encrypted && entrykey != none {
			// see if you have issuses: https://github.com/vlang/v/issues/22936
			if entrykey.len == 0 {
				panic('Not encrypted but got entrykey (${entrykey})!')
			}
		}
	} // end bare for (while)

	if is_stuffit_encrypted && entrykey == none {
		println('Encryted but did not set entrykey')
	}

	return Sit{
		entrykey:  		entrykey
		totalsize: 		totalsize
		root:      		root
	}
}

// If known, return type of compression
fn name_of_compression_method(method u8) ?string {
	match method {
		// was, method & 0x0f. Now expecting method to be method
		0 { return 'StuffIt' } // was, None
		1 { return 'RLE' }
		2 { return 'Compress' }
		3 { return 'Huffman' }
		5 { return 'LZAH' }
		6 { return 'Fixed Huffman' }
		7 { return 'MW' }
		// Jumps
		13 { return 'LZ+Huffman' }
		14 { return 'Installer' }
		15 { return 'Arsenic' }
		else { return none }
	}
}
