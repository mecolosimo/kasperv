module sit

pub struct SitConfig {
pub:
	sit_file		string
	archive_hash	[]u8
	wildcard 		bool
	debug			bool
	mkey			?[]u8
	sit				?Sit
pub mut:
	passwd			string
}

// Make a new SitConfig
pub fn new_config(sit_file string, archive_hash []u8, wildcard bool, debug bool,
				  passwd string, mkey ?[]u8, sit ?Sit) SitConfig {
	mut config := SitConfig{
			sit_file:		sit_file
			passwd:			passwd
			archive_hash: 	archive_hash
			wildcard: 		wildcard
			debug:			debug
		}
	if mk := mkey {
		if s := sit {
			// v seems it can do two guards in an if statement
			// really not expecting mkey without sit
			if ek := s.entrykey {
				if ek.len < 16 {
					panic("entrykey length less than 16 (${ek.len})!")
				}
			}
			config = SitConfig{
				sit_file:		sit_file
				passwd:			passwd
				archive_hash: 	archive_hash
				wildcard: 		wildcard
				debug:			debug
				mkey:			mk
				sit:			s
			} 
		} else {
			panic("Missing Sit config!")
		}
	} else {
		if s := sit {
			panic("Missing mkey but have Sit!")
		}
	}
	return config
}
