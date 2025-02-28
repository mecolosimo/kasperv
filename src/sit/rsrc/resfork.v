// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
// Adpated from https://github.com/jorio/rsrcdump
// Also see:
// 	http://formats.kaitai.io/compressed_resource/
// 	https://github.com/dgelessus/python-rsrcfork
module rsrc

import os

import bytes

type ResType = []u8 // bytes, a byte is a type in builtin/int.v

// Really name and type are in Mac OS Roman, which is mostly ASCII (128 of which are identical to ASCII)
pub struct Resource {
pub:
	type  ResType @[required; xdoc: 'Entry Id (FourCCs) of the resource type.']
	num   i32     @[required; xdoc: 'ID of this resource. Should be unique within the resource type.']
	data  []u8    @[xdoc: 'Raw data of the resource.']
	name  []u8    @[xdoc: 'Raw resource name. Typically encoded as MacRoman.']
	flags u32     @[xdoc: 'Flag byte.']
	junk  u32     @[xdoc: 'Some 32-bit handle. This should be 0, but some files in the wild contain some junk here instead.']
	order u32 = u32(0xFFFFFFFF)     @[xdoc: 'Order in which the resource appears in the original resource fork. 0xFFFFFFFF indicates the order is unknown']
	data_offset	u32 @[xdoc: 'Offset of data']
}

pub fn (r Resource) str() string {
	return '`${convert_mac_roman_to_utf8(r.type)}` num: ${r.num}'
}

pub fn (r Resource) desc() string {
	t := convert_mac_roman_to_utf8(r.type)
	return "${t}#${r.num}"
}

pub fn (r Resource) type_str() string {
	return convert_mac_roman_to_utf8(r.type)
}

pub fn (r Resource) name_str() string {
	return convert_mac_roman_to_utf8(r.name)
}

pub struct Resource_Fork {
pub mut:
	tree							map[string]map[u32]Resource @[xdoc: 'Map of all resources in the resource fork.']	// ResType, map[i32]Resource{} -> ResType type_str(), map
pub:
	junk_nextresmap		u32	@[required; xdox: 'Junk 32-bit value.']
	junk_filerefnum		u32 @[required; xdox: 'Junk 32-bit value.']
	file_attributes 	u32 @[required; xdox: 'Finder file attributes.']
}

pub fn new_resource_fork_from_buffer(buf []u8) !Resource_Fork {
	if buf.len == 0 {
		return error('Buffer is empty')
	} else {
		// was unpack_from(">LLLL", data, 0)
		data_offset := bytes.uint_32_be(buf, 0)
		map_offset := bytes.uint_32_be(buf, 4)
		data_length := bytes.uint_32_be(buf, 8)
		map_length := bytes.uint_32_be(buf, 12)

		//println('\tdata_offset:0x${data_offset:X}\tdata_length:0x${data_length:X}')
		//println('\tmap_offset:0x${map_offset:X}\tmap_length:0x${map_length:X}')

		if data_offset + data_length > buf.len || map_offset + map_length > buf.len{
			return error("offsets/lengths in header are nonsense")
		}

		//u_data = Unpacker(data[data_offset: data_offset + data_length])
		//u_map = Unpacker(data[map_offset: map_offset + map_length])
		u_data_bytes := buf[data_offset .. data_offset + data_length]
		u_map_bytes  := buf[map_offset .. map_offset + map_length]

		// u_map.skip(16)
		// u_map.unpack(">LHH"), big-endian, unsigned long (4 bytes), unsigned short (2 bytes), unsigned short
		junk_nextresmap := bytes.uint_32_be(u_map_bytes, 16)
		junk_filerefnum := bytes.uint_16_be(u_map_bytes, 20 )
		file_attributes := bytes.uint_16_be(u_map_bytes, 22 )

		// u_map.unpack(">HHH")
		//typelist_offset_in_map := bytes.uint_16_be(u_map_bytes, 24)
		namelist_offset_in_map := bytes.uint_16_be(u_map_bytes, 26)
		mut num_types := bytes.uint_16_be(u_map_bytes, 28)
		num_types += 1	// because for loop is not inclusive

		// can we put an end to these?
		// u_types := u_map_bytes[typelist_offset_in_map..]
		u_names := u_map_bytes[namelist_offset_in_map..]
		//println("\tu_map_bytes size: ${u_map_bytes.len}")
		if num_types == 1 {
			return error('rsrc is empty')
		}

		mut tree := map[string]map[u32]Resource{}
		mut offset_map := 30
		mut offset_data := 0
		for _ in 0 .. num_types {
			// u_map.unpack(">4sHH")
			res_type := u_map_bytes[offset_map .. offset_map + 4]
			offset_map += 4
			res_count := bytes.uint_16_be(u_map_bytes, offset_map ) + 1
			offset_map += 2
			reslist_offset := bytes.uint_16_be(u_map_bytes, offset_map )
			offset_map += 2
			//println("\tres_type: ${convert_mac_roman_to_utf8(res_type)}")

			if convert_mac_roman_to_utf8(res_type) in tree {
				return error('${convert_mac_roman_to_utf8(res_type)} already processed!')
			}

			for j in 0 .. res_count {
				res_id := bytes.int_16_be(u_map_bytes, reslist_offset)
				res_name_offset := bytes.uint_16_be(u_map_bytes, reslist_offset + 2)
				res_packed_attr := bytes.uint_32_be(u_map_bytes, reslist_offset + 4)
				res_junk := bytes.uint_32_be(u_map_bytes, reslist_offset + 8)

				// unpack attributes
				res_flags := (res_packed_attr & 0xFF000000) >> 24
				//res_data_offset := (res_packed_attr & 0x00FFFFFF)

				// check compressed flag. Not sure this is correct.
				if (res_flags != 0) && (res_flags & 1) == 0 {
					return error("Compressed resources are not supported")
				}

				// fetch name, if any given
				mut res_name := []u8{}
				if u_names.len >= res_name_offset && res_name_offset != 0xFFFF {
					// pascal style-string
					len := u_names[res_name_offset .. res_name_offset + 1]
					res_name = u_names[res_name_offset + 1 .. res_name_offset + 1 + len[0]].clone()
				}

				// fetch resource data from data section
				res_size := bytes.int_32_be(u_data_bytes, offset_data)	// u_data.unpack(">i")[0]
				offset_data += 4
				res_data := u_data_bytes[offset_data .. offset_data + res_size]

				r := Resource{
					type: res_type
					num: res_id
					data: res_data
					name: res_name
					flags: res_flags
					junk: res_junk
					order: j
					data_offset: u32(offset_data)
				}

				offset_data += res_size

				if r.type_str() in tree {
					if r.order in tree[r.type_str()] {
						panic("Idenical oder given!")
					} else {
						tree[r.type_str()][r.order] = r
					}
				} else {
					tree[r.type_str()][r.order] = r
				}
			} // for
		} // for i in 0 .. num_types

	return Resource_Fork {
		tree: tree
		junk_nextresmap: junk_nextresmap
		junk_filerefnum: junk_filerefnum
		file_attributes: file_attributes
		}
	} // if buf
}

pub fn new_resource_fork_from_file(path string) !Resource_Fork {
	p := path.trim_space()
	bn := os.base(p)  	// base (name) If the path is empty, base returns ".", similar to file_name
	f := os.file_name(p)
	d := os.dir(p)		// Directory
	// TODO: Implement Apple Single/Double name conversion
	if os.exists( os.join_path(d, "._" + f ) ) {
		// Get data				
		mut buf := os.read_bytes( os.join_path(d, "._" + f ) ) or { panic('${err}') }

		return apple_single_double(buf)
	} else if os.exists(p) {
		// v's string and file utiles needs work IMHO
		// SheepSaver seems to saves the resource fork under .rsrc There are also turds under .finf
		dirs := os.dir(p)
		if dirs.len > 0 {
			r_p := os.join_path(dirs, ".rsrc", bn)

			// see if rsrc fork exists
			if os.exists(r_p) {
				fi := os.inode(r_p)
				if fi.size == 0 {
					return error("No data!")
				}
				if fi.size < 32 { // >LLLL16x, big-endian, unsigned long (4 bytes), unsigned long, unsigned long, unsigned long, 16 pad bytes
					return error("data is too small to contain a valid resource fork header")
				}
				// Get data				
				mut buf := os.read_bytes(r_p) or { panic('${err}') }
				return new_resource_fork_from_buffer(buf)
			} else {
				return error('No .rsrc dir found!')
			}
		} else {
			panic("What is going on?")
		}
	} else {
		// os.exits
		return error('Doesnot exist! ${path}')
	}
}