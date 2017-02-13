-define(LLC_DSAP_SNAP, 16#aa).
-define(LLC_SSAP_SNAP, 16#aa).
-define(LLC_CNTL_SNAP, 3).
-define(SNAP_ORG_ETHERNET, 0,0,0).

-define(ETH_P_PAE, 16#888e).          %% Port Access Entity (IEEE 802.1X)

-record(ccmp, {rsn,
	       cipher_suite,
	       replay_counter,
	       pre_master_key,
	       nonce,
	       kck,
	       kek,
	       tk}).
