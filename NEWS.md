capwap
======

Erlang CAPWAP AC implementation.

Version 1.0.1 - xx Sep 2013
---------------------------

* add work arround for pre 1.0 WTP statistics event and handle
  broken (little-endian) encoding
* add RADIUS accounting for WTP sessions
* add WTP WWAN statistics in RADIUS accounting
  (requires ctld 1.0.1 and eradius 0.3.1)

Version 1.0.0 - 17 Sep 2013
---------------------------

* Support for local mac and split mac mode
* Allows encryoted and plain WTP control session
* Support for WTP session take over when using encrypted control channel
* Support for station take over
