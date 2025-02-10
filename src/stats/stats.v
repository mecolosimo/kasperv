// Copyright (c) 2025 Marc E. Colosimo. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

import math

// choose n-choose 
// EXPECTED VALUES
// x choose x = 1
// 9 choose 4 = 126
// 52 choose 5 = 2598960
// 64 choose 33 = 1.777090076065542336E18
// see: https://stackoverflow.com/a/12983878/4285191
pub fn choose(n int, k int) f64 {
	if k < 0 { return 0.0 }
	if k == 0 { return 0.0 }
    mut sum := 0.0
    for i := 0; i < k; i++ {
        sum += math.log10(n - i)
        sum -= math.log10(i + 1)
    }
	return math.trunc(math.pow(10, sum))
}