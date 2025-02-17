//  Public-domain functions for dealing with Unicode, UTF-8, and Mac Roman strings,
//  as used in SWTSG (alienryderflex.com/crawl).
//
//  coded by Darel Rex Finley, 2008
//  adapted to v by Marc E. Colosimo from https://alienryderflex.com/utf-8/
module rsrc

import strings

const  utf8_chars = 2097152

//  Table to convert the Mac OS Roman characters 0x80-0xFF to u32 (not UTF-8, basically Unicode).
//  Derived from the table at:  http://alanwood.net/demos/macroman.html
const mac_roman_to_unicode := [
  u32(196) ,  197,  199,  201,  209,  214,  220,  225,  224,  226,  228,  227,  229,  231,   233,   232,
  234  ,  235,  237,  236,  238,  239,  241,  243,  242,  244,  246,  245,  250,  249,   251,   252,
  8224 ,  176,  162,  163,  167, 8226,  182,  223,  174,  169, 8482,  180,  168, 8800,   198,   216,
  8734 ,  177, 8804, 8805,  165,  181, 8706, 8721, 8719,  960, 8747,  170,  186,  937,   230,   248,
  191  ,  161,  172, 8730,  402, 8776, 8710,  171,  187, 8230,  160,  192,  195,  213,   338,   339,
  8211 , 8212, 8220, 8221, 8216, 8217,  247, 9674,  255,  376, 8260, 8364, 8249, 8250, 64257, 64258,
  8225 ,  183, 8218, 8222, 8240,  194,  202,  193,  203,  200,  205,  206,  207,  204,   211,   212,
  63743,  210,  218,  219,  217,  305,  710,  732,  175,  728,  729,  730,  184,  733,   731,   711
]

//  Convert a character from Mac OS Roman text to Unicode.
//  was void convertMacCharToUnicode(long *c)
fn convert_mac_char_to_unicode(c u8) ?u32 {
	if c >= 128 && c < 256 { return mac_roman_to_unicode[c-128] } else { return none }
}


//  Converts a Mac OS Roman C-string to a UTF8 v string.
//  was void convertMacStrToUnicodeLongStr(long *longStr, BYTE *macStr, long max)
pub fn convert_mac_roman_to_utf8(mac_str []u8) string {
	if mac_str.len > 0 {
		mut sb := strings.new_builder(100)
		for c in mac_str {
			if r := convert_mac_char_to_unicode(c) {
				sb.write_rune(rune(r))
			} else {
				// should check range
				sb.write_byte(c)
			}
		}
		return sb.str()
	} else {
		return ""
	}
}
