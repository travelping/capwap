capwap
======

Erlang CAPWAP AC implementation.

Version 1.5.0 - xx Feb 2015
---------------------------

* upgrade to Erlang R17
* adjust for ctld v1.3.0 changes
* added STA and WTP Accounting

Version 1.4.2 - 21 Jan 2015
---------------------------

* add list_stations DP function

Version 1.4.1 - 19 Jan 2015
---------------------------

* enhance CAPWAP loggging
* fix capwap-dp resource leakage in del_station event and detach station commands
* handle disconnected data path gracefully
* remove openflow left overs

Version 1.4.0 - 13 Jan 2015
---------------------------

* change to use capwap-dp as data path element
* remove WTP event log

Version 1.3.2 - 26 Nov 2014
---------------------------

* force SO_REUSEADDR on the CAPWAP socket
* handle packet with invalid CAPWAP headers

Version 1.3.1 - 06 Nov 2014
---------------------------

* change station ctld reporting to include the WTP-Id and Session-Id

Version 1.3.0 - 05 Sep 2014
---------------------------

* add support for packet fragmentation (reassembly and fragment) for control
  channel (fragmented data channel messages are not handled)

Version 1.2.5 - 21 Aug 2014
---------------------------

* fix decoding of GPS time information
* fix decoding of MCC and MNC in statistics element

Version 1.2.4 - 07 Jun 2014
---------------------------

* send all WTP version attributes to ctld

Version 1.2.3 - 17 Jul 2014
---------------------------

* The statemachines which represent stations are actually stopped.
* Station limitation per WTP fixed.

Version 1.2.2 -  4 Jul 2014
---------------------------

* Fixes an error with WTP interrim accounting

Version 1.2.1 - 20 Jun 2014
---------------------------

* improve CAPWAP Request/Reply logging
* forwarding gps_last_acquired_position data to ctld_session.
* add wlan hold time element, default value is 15 seconds.
* cherry-pick from v1.1 branch: for add_flow response to flsc, add a
   parameter to control wether the current packet gets dropped or sent
* cherry-pick from v1.1 branch: convert all debug logging to use lager

Version 1.2.0 - 20 Mar 2014
---------------------------

* internal tests throw a mock wtp implementation
* implement request queue, allow only one outstanding request
* add power save mode attribute to the coder
* capwap ac logs only in one logfile

Version 1.1.5 - 21 Feb 2014
---------------------------

* add new Travelping attributes
* add initial capwap shell
* add initial implementation of update firmware

Version 1.1.4 - 07 Jan 2014
---------------------------

* fix decoding of wireless binding data

Version 1.1.3 - 16 Oct 2013
---------------------------

* Robuster main socket handling, make sure unexpected incomming data
  is unable to crash the AC
* Handling misinterpretation of ac list element in older versions of WTP

Version 1.1.2 - 27 Sep 2013
---------------------------

* handle wtp version decoding errors in discovery gracefully

Version 1.1.1 - 20 Sep 2013
---------------------------

* strict Echo Timeout handling for the control channel
* Data Channel KeepAlive messages are now RFC compliant, invalid
  messages are still accepted
* Send Accounting-Stop on WTP connection loss

Version 1.1.0 - 20 Sep 2013
---------------------------

* Add work arround for pre 1.0 WTP statistics event and handle
  broken (little-endian) encoding
* Add RADIUS accounting for WTP sessions
* Add WTP WWAN statistics in RADIUS accounting
  (requires ctld 1.0.1 and eradius 0.3.1)

Version 1.0.0 - 17 Sep 2013
---------------------------

* Support for local mac and split mac mode
* Allows encryoted and plain WTP control session
* Support for WTP session take over when using encrypted control channel
* Support for station take over
