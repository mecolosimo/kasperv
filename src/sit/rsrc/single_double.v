// Copyright (c) 2025 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
// Reads Apple Single/Double Format
// see: https://web.archive.org/web/20180311140826/http://kaiser-edv.de/documents/AppleSingle_AppleDouble.pdf
module rsrc

import bytes

pub enum Predefined_Entry_ID {
	none
	data_fork  		= 1 		@[xdoc: 'Data fork']
	resource_rork 		 		@[xodc: 'Resource fork']
	real_name 					@[xdoc: 'File’s name as created on home file system']
	comment 			 		@[xdoc: 'Standard Macintosh comment']
	icon_b_w 					@[xdoc: 'Standard Macintosh black and white icon']
	icon_color					@[xdoc: 'Macintosh color icon']
	file_dates_into				@[xdoc: 'File creation date, modification date, and so on']
	finder_info 				@[xdoc: 'Standard Macintosh Finder information']
	machintosh_file_info 		@[xdoc: 'Macintosh file information, attributes, and so on']
	prodoc_file_info 			@[xdoc: 'ProDOS file information, attributes, and so on']
	ms_dos_file		 			@[xdoc: 'MS-DOS file information, attributes, and so on']
	short_name					@[xdoc: 'AFP short name']
	afp_file_info				@[xdoc: 'AFP file information, attributes, and so on']
	directory_id	= 15 		@[xdoc: 'AFP directory ID']
}

struct Entry {
	offset	 	u32	@[xdoc: 'Offset, an unsigned 32-bit number, shows the offset from the beginning of
the file to the beginning of the entry’s data.']
	length 		u32 @[xdoc: 'an unsigned 32-bit number, shows the length of the data in bytes.
The length can be 0.']
}

pub fn apple_single_double(buf []u8) !Resource_Fork {
	if buf.len == 0 {
		return error('Buffer is empty')
	} else {
		magic_number := bytes.uint_32_be(buf, 0)
		if !(magic_number == 0x051600 || magic_number == 0x051607) {
			return error('Magic Number incorrect ${magic_number:X}!')
		}
		// version_number := bytes.uint_32_be(buf, 4)
		// filler; 16 bytes
		num_entries := bytes.uint_16_be(buf, 24)
		mut entries := map[u32]Entry{} // Apple reserves the range of entry IDs from 1 to $7FFFFFFF.
		for i := 0; i < num_entries; i++ {
			entry_id := bytes.uint_32_be(buf, 26 + (i * 12))
			offset := bytes.uint_32_be(buf, 30 + (i * 12))
			length := bytes.uint_32_be(buf, 34 + (i * 12))
			if entry_id in entries {
				return error('${entry_id} already processed!') // need to convert u32 to []u8!
			}
			entries[entry_id] = Entry{
				offset: 	offset
				length:		length
			}
		}
		if u8(Predefined_Entry_ID.resource_rork) in entries {
			rsrc := entries[u8(Predefined_Entry_ID.resource_rork)]
			if rsrc.offset + rsrc.length > buf.len {
				return error('\toffset plus length greater than bug length!')
			}
			return new_resource_fork_from_buffer(buf[rsrc.offset .. rsrc.offset + rsrc.length])
		}
	}
	return error('Unimplemented!')
}