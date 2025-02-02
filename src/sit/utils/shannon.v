// Copyright (c) 2025 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module utils

import math

// Counts unique items V where V is a valid map key.
// count[int]([1, 2, 2, 3, 3, 3]) -> {1: 1, 2: 2, 3: 3}
pub fn count[V](array []V) map[V]int {
	// simulare to the builtin group_by
	mut result := map[V]int
	
	for v in array {
		if v in result {
			result[v] = result[v] + 1
		} else {
			result[v] = 1
		}
	}
	
	return result
}

// shannon bit (log2) entropy calculation
pub fn shannon(bytes []u8) f64 {
	cnts := count[u8](bytes)
	// can't just divide whole map in v
	mut symbol_set := map[u8]f64{}
	for k, v in cnts {
		if k in symbol_set { panic('What!') }
		symbol_set[k] = f64(v) / bytes.len
	}
	mut bits := []f64{}
	// [round(symbol_set[symbol] * math.log2(symbol_set[symbol]), 5) for symbol in symbol_set]
	for _, v in symbol_set {
		bits << v * math.log2(v)
	}
	mut sum := 0.0
	for b in bits { sum = sum + b }

	return -1 * math.round_sig(sum, 5)
}