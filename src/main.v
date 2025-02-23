// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module main

import encoding.hex 
import flag
import io
import os
import time

import progressbar

import sit
import sit.rsrc

const sit5_archiveversion = 5
const sit5_id = [0xA5, 0xA5, 0xA5,0xA5]
const sit5_archiveflags_14bytes = 0x10
const sit5_archiveflags_20bytes = 0x20
const sit5_archiveflags_crypted = 0x80

const debug = true

@[xdoc: 'Kasper: a sit5 password recovery tool.']
@[version: '0.0.6']
@[name: 'kasper']
pub struct Config {
	passwd			string 	@[short: p; xdoc: 'The password to try']
	file			string 	@[short: f; xdoc: 'A password file with a password per line']
	sit				string 	@[short: s; xdoc: 'The password protected SIT archive']
	wildcard 		bool 	@[short: w; xdoc: 'Expand astericks in passwd']
	num_threads		u8 = 1	@[short: n; xdoc: 'Number of threads to use']
	mkey 			?string @[short: m; xdoc: 'MKey found in rsrc fork, will try to parse it out if not given.']
	help 			bool 	@[short: h; xdoc: 'Help']
	debug			bool 	@[short: d; xdoc: 'Debug']
}

// run kasper on sit5 archive
fn kaspser_five(config Config, mut f os.File) ! {

	mut pb_cnt := u64(1)
	if config.passwd.contains('*') && config.wildcard {
		// how many? and update progress bar
		println("Calculating number of guesses. Please wait...")
		pb_cnt = sit.calc_samples(config.passwd.count('*'))
		println("\tCalculated ${pb_cnt} guesses.")	
	}
	mut pb := progressbar.progressbar_new("SIT5", pb_cnt ) 

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

		sit_config := sit.new_config(config.sit, archive_hash, config.wildcard,
										config.debug, config.num_threads,
										config.passwd, none, none)

		// start processing threads
		query_ch := chan string{cap: 95}
		result_ch := chan string{cap: 95}
		for _ in 0 .. config.num_threads {
			go producer(query_ch, result_ch, sit_config, mut pb, sit.check_sit5_password)
		}

		// starting consumer
		con := go consumer(result_ch, mut pb, pb.progessbar_max())

		// start filling the queue, don't expect many (if any) results
		sit.replace_asterix(sit_config, query_ch)

		con.wait()	

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

			sit_config := sit.new_config(config.sit, archive_hash, config.wildcard,
												 config.debug, config.num_threads,
												 config.passwd.trim_space(),
												 none, none)

			// start processing threads
			query_ch := chan string{cap: 95}
			result_ch := chan string{cap: 95}
			for _ in 0 .. config.num_threads {
				go producer(query_ch, result_ch, sit_config, mut pb, sit.check_sit5_password)
			}

			// starting consumer
			con := go consumer(result_ch, mut pb, pb.progessbar_max())

			// start filling the queue, don't expect many (if any) results
			sit.replace_asterix(sit_config, query_ch)

			con.wait()	
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
		sit_r := sit.parse(mut f) or { panic("Couldn't parse SIT!") }
		println("SIT!")
		mut mkey := ?[]u8(none)
		if mk := config.mkey {
			if mk.len % 2 == 0 {
				mkey = hex.decode(mk) or { panic('Unable to decode given MKey: ${mk}')}
			}
		} else {
			println("Not given MKey! Looking for it in a rsrc file.")
			// see if .rcrs file exists
			res := rsrc.new_resource_fork_from_file(sit_file_path) or { panic('No MKey found or given: ${err}') }
			// Not none, see if MKey is there
			if 'MKey' in res.tree { // bad does v support map interface?
				mkey_rsrc := res.tree['MKey'].clone()
				if mkey_rsrc.len == 1 && 0 in mkey_rsrc {
					println("\tFound MKey in a resource (rsrc) fork.")
					mkey = mkey_rsrc[0].data.clone()
				} else {
					dump(mkey_rsrc)
					panic('Found a resource fork (rsrc) but not MKey a the fork!')
				}
			} else {
				panic('No MKey in rsrc fork!')
			}
		
		} 


		mut check_passwd := config.passwd
		if config.passwd.len > 8 {
			check_passwd = config.passwd[0 .. 8]
			println("\tpasswd too long using: ${check_passwd}")
		} 

		if mk := mkey {

			mut pb_cnt := u64(1)
			if config.passwd.contains('*') && config.wildcard {
				// how many? and update progress bar
				println("Calculating number of guesses. Please wait...")
				pb_cnt = sit.calc_samples(config.passwd.count('*'))
				println("\tCalculated ${pb_cnt} guesses.")
			}
			mut pb := progressbar.progressbar_new("SIT", pb_cnt)
			
			sit_config := sit.new_config(
				config.sit, []u8{}, config.wildcard, 
				config.debug, config.num_threads, check_passwd,
				mk, sit_r)

			// start processing threads
			query_ch := chan string{cap: 95}
			result_ch := chan string{cap: 95}
			for _ in 0 .. config.num_threads {
				go producer(query_ch, result_ch, sit_config, mut pb, sit.check_sit_password)
			}

			// starting consumer
			con := go consumer(result_ch, mut pb, pb.progessbar_max())

			// start filling the queue, don't expect many (if any) results
			sit.replace_asterix(sit_config, query_ch)

			con.wait()	

		} else {
			panic('encpyted but NO MKey found!')
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
