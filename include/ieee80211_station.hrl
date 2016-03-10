-record(sta_cap, {
	  wmm = false        :: boolean(),
	  sgi_20mhz = 0      :: boolean(),
	  sgi_40mhz = 0      :: boolean(),
	  smps = disabled    :: atom(),
	  back_delay = false :: boolean(),
	  ampdu_density = 0  :: integer(),
	  ampdu_factor = 0   :: integer(),
	  rx_mask = <<0,0,0,0,0,0,0,0,0,0>> :: binary(),
	  rx_highest = 0     :: integer()
	 }).
