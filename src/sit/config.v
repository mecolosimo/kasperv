module sit

pub struct SitConfig {
pub:
	sit_file		string
	archive_hash	[]u8
	wildcard 		bool
	num_threads		u8
	debug			bool
	mkey			?[]u8
	sit				?Sit

	passwd			string	@[xdoc: 'The original password']

pub mut:
	search			string	@[xdoc: 'The search password']
}

// Make a new SitConfig
pub fn new_config(sit_file string, archive_hash []u8,
				  wildcard bool, debug bool, num_threads u8,
				  passwd string, mkey ?[]u8, sit ?Sit) SitConfig {
	mut config := SitConfig{
			sit_file:		sit_file
			passwd:			passwd
			archive_hash: 	archive_hash
			wildcard: 		wildcard
			num_threads: 	num_threads
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
		if sit != none {
			panic("Missing mkey but have Sit!")
		}
	}
	return config
}
