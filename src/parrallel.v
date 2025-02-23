// Copyright (c) 2024 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module main

import progressbar

import sit

fn producer(in_ch chan string, out_ch chan string,
			config sit.SitConfig, 
			mut pb &progressbar.Progessbar,
			search fn (string, sit.SitConfig) string) {
	for {
		q := <- in_ch or { break }	// hopefully blocks or is closed	
		passwd_match := search(q, config)
		pb.progressbar_inc()
		if passwd_match.len > 0 {
			out_ch <- passwd_match	// might block
		} else {
			out_ch <- ""
		}
	}
}

fn consumer(in_ch chan string, mut pb &progressbar.Progessbar, num_threads u64) {
	mut passwd_matches := []string{}
	mut done := 0
	for {
		passwd_match := <- in_ch or { break }
		if passwd_match == "" {
			done += 1
		} else {
			passwd_matches << passwd_match
		}

		if done >= num_threads {
			pb.progressbar_finish()
			if passwd_matches.len > 0 {
				println("Matched:")
				for p in passwd_matches {
					println("\t${p}")
				}
			}
			break
		}
	}
}