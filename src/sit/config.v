module sit

pub struct SitConfig {
pub:
	sit						string
	archive_hash	[]u8
	wildcard 			bool
	debug					bool
pub mut:
	passwd				string
	index 				int = -1		@[xdoc: 'the index position of an asterix in the passwd']
}

// Make a new SitConfig
pub fn new_config(sit string, archive_hash []u8, wildcard bool, debug bool, passwd string) SitConfig {
	return SitConfig{
		passwd:					passwd
		archive_hash: 	archive_hash
		wildcard: 			wildcard
		debug:					debug
	}
}
