// Copyright (c) 2025 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module sit

// index_after returns the position of the input string p,
// starting search from `from_index` position.
@[direct_array_access]
pub fn index_of(s string, p string, from_index ?int) ?int {
	// based on v's index_of and on
	// https://docs.oracle.com/javase/6/docs/api/java/lang/String.html#indexOf(java.lang.String,%20int)
	// and https://docs.python.org/3/library/stdtypes.html#str.find
	// see issue #804
	mut strt := 0
	if from_index != none {
		strt = from_index
		if strt < 0 {
			strt = 0
		}
	}
	if p.len > s.len {
			return none
	}
	if strt >= s.len {
			return none
	}
	mut i := strt
	for i < s.len {
			mut j := 0
			mut ii := i
			for j < p.len &&
				ii < s.len &&
				unsafe { s.str[ii] == p.str[j] } {
					j++
					ii++
			}
			if j == p.len {
					return i
			}
			i++
	}
	return none
}
