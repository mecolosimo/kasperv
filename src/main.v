// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module main

import flag
import io
import os
import time

import sit
import sit.rsrc

const sit5_archiveversion = 5
const sit5_id = [0xA5, 0xA5, 0xA5,0xA5]
const sit5_archiveflags_14bytes = 0x10
const sit5_archiveflags_20bytes = 0x20
const sit5_archiveflags_crypted = 0x80

const debug = true

@[xdoc: 'Kasper: a sit5 password recovery tool.']
@[version: '0.0.2']
@[name: 'kasper']
pub struct Config {
	passwd		string 	@[short: p; xdoc: 'The password to try']
	file			string 	@[short: f; xdoc: 'A password file with a password per line']
	sit				string 	@[short: s; xdoc: 'The password protected SIT archive']
	wildcard 	bool 	@[short: w; xdoc: 'Expand astericks in passwd']
	mkey 			?string @[short: m; xdoc: 'MKey found in rsrc fork, will try to parse it out if not given.']
	help 			bool 	@[short: h; xdoc: 'Help']
	debug			bool 	@[short: d; xdoc: 'Debug']
}

// run kasper on sit5 archive
fn kaspser_five(config Config, mut f os.File) ! {
	mut archive_hash := []u8{len: sit.sit5_key_length, cap: sit.sit5_key_length, init: 0}

	f.seek(i64(sizeof(u8))*82, .start) or { panic('${err}') } // skip to version, 0x52
	version := f.read_raw[u8]() or { panic('${err}') }
	flags := f.read_raw[u8]() or { panic('${err}') }

	if config.debug {
		println("flags: ${flags}")
	}

	if version != sit5_archiveversion {
		panic('NOT SIT version 5: version ${version}')
	}

	// v's file method are odd can't use read_bytes with seek!
	f.seek(i64(sizeof(u8))*16, .current) or { panic('${err}')}
	if flags&sit5_archiveflags_14bytes != 0{
		f.seek(i64(sizeof(u8))*14, .current) or { panic('${err}') }
	}

	if flags&sit5_archiveflags_20bytes != 0 {
		// skip over comment
		f.seek(i64(sizeof(u32)), .current) or { panic('${err}') }
	}

	if flags&sit5_archiveflags_crypted == 0 {
		panic("Not encrypted!")
	}

	// Read encrypted password
	// v's file utils suck so does c's :(
	f.read_bytes_into(u64(f.tell() or { panic('${err}') }) + 1,
					mut archive_hash) or { panic('${err}') }

	if config.debug {
		println("archive_hash: ${archive_hash}")
	}

	if config.passwd.len > 0 {
		println('Checking ${config.passwd}')

		kasper_config := sit.new_config(config.sit, archive_hash, config.wildcard, config.debug, config.passwd)

		sit.check_5_password(kasper_config) or { panic('${err}')}
	}

	// check if password and file given is main
	if config.file.trim_space().len > 0 {
		println("Checking words in ${config.file}")

		mut file_path := os.abs_path(config.file)

		if !os.exists(file_path) {
			return error("password file path doesn't exist")
		}

		mut password_file := os.open(file_path) or { panic('${err}') }
		defer {
			password_file.close()
		}

		mut reader := io.new_buffered_reader(reader: password_file) // not string_builder!
		mut cnt := 0
		mut sw := time.new_stopwatch()
		sw.start()
		for {
			password := reader.read_line() or { break }	//could be cleaner

			if config.debug {
				println('Checking: ${password}')
			}

			kasper_file_config := sit.SitConfig{
				passwd:			password.trim_space()
				archive_hash: 	archive_hash
				wildcard: 		false		// just use words as passwords
				debug:			config.debug
			}

			sit.check_5_password(kasper_file_config) or { panic('${err}')}

			// Simple old school way of showing progress
			if cnt % 1000 == 0 {
				print("Checked ${cnt} passwords in ${sw.elapsed()}\r")
			}

			cnt += 1
		}

		sw.stop()
		println("Checked ${cnt} total passwords in ${sw.elapsed()}")
	}
}

fn kasper(config Config) ! {

	mut sit_file_path :=  if os.is_abs_path(config.sit) {
			config.sit
		} else {
			if config.sit[0] == u8(126) { // ~
				println("Expanding ~")
				os.expand_tilde_to_home(config.sit)
			} else {
				os.abs_path(config.sit)
			}
		}
	if !os.is_file(sit_file_path) {
		panic("${sit_file_path} is NOT a file!")
	}

	// debug
	if config.debug {
		println(sit_file_path)
	}

	if !os.exists(sit_file_path) && os.is_file(sit_file_path) {
		return error("SIT source path doesn't exist")
	}

	mut f := os.open(sit_file_path) or { panic('${err}') }
	defer {
		f.close()
	}

	if sit.is_sit(f) {
		println("SIT!")
		sit_r := sit.parse(mut f) or { panic("Couldn't parse SIT!") }
		println("entrykey: ${sit_r.entrykey}")
		mut mkey := ?[]u8(none)
		if config.mkey == none {
			println("MKey is none!")
			// see if .rcrs file exists
			res := rsrc.new_resource_fork(sit_file_path)
			if r := res {
				// Not none, see if MKey is there
				if 'MKey' in r.tree { // bad does v support map interface?
					mkey_rsrc := r.tree['MKey'].clone()
						if mkey_rsrc.len == 1 && 0 in mkey_rsrc {
							println('Found ${mkey_rsrc[0]} ${mkey_rsrc[0].data}!')
							mkey = mkey_rsrc[0].data.clone()
						}
				} else {
					panic('No MKey in rsrc fork!')
				}
			} else {
				panic('No MKey found or given!')
			}
		}
		if mk := mkey {
			println('ok')
		}
	} else if sit.is_sit5(f) {
		kaspser_five(config, mut f)!
	} else if sit.is_sit_zip(f) {
		panic("Don't support zip sit archives!")
	}
}

fn main() {
    // Map POSIX and GNU style flags found in `os.args` to fields on struct `T`
    config, no_matches := flag.to_struct[Config](os.args, skip: 1)!

    if no_matches.len > 0 {
        println('The following flags could not be mapped to any fields on the struct: ${no_matches}')
    }

    if config.help {
        // Generate and layout (a configuable) documentation for the flags
        documentation := flag.to_doc[Config](
			fields: {
				'sit':			'This specifics the location of the password protected SIT archive'
				'file': 		'A password file with a password per line'
				'passwd':		'This is the password to try'
				'wildcard':		'This flag is to specify whether the passwd contains astericks that should be expanded'
				'debug':		'This flag is to specify whether to display debug info'
			}
		)!
		println(documentation)
		exit(0)
	}

	println('Kasper: a sit5 password recovery tool.')
	println('')

	if config.sit.trim_space().len == 0 {
		panic("No sit file given!")
	}

	// better way to check?
	if config.passwd.len != 0 && config.file.trim_space().len != 0 {
		panic("Expected password or file. NOT both!")
	}

	kasper(config) or { panic('${err}') }
	println("Done")
}
