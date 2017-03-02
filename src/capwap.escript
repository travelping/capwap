#!/usr/bin/env escript
%%! -hidden -connect_all false -smp disable -kernel inet_dist_use_interface {127,0,0,1}

%% Copyright (C) 2013-2017, Travelping GmbH <info@travelping.com>

%% This program is free software: you can redistribute it and/or modify
%% it under the terms of the GNU Affero General Public License as published by
%% the Free Software Foundation, either version 3 of the License, or
%% (at your option) any later version.

%% This program is distributed in the hope that it will be useful,
%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%% GNU Affero General Public License for more details.

%% You should have received a copy of the GNU Affero General Public License
%% along with this program.  If not, see <http://www.gnu.org/licenses/>.

-mode(compile).

-include("../include/capwap_packet.hrl").
-include("../include/capwap_config.hrl").
-include("../include/capwap_ac.hrl").

main(_, []) ->
    help();

main(_, ["list"]) ->
    WTPs = rpc(capwap, list_wtps, []),
    [io:format("~s : ~s:~w~n", [CommonName, inet_parse:ntoa(Address), Port]) || {CommonName, {Address, Port}} <- WTPs];

main(_, ["show", CN]) ->
    case rpc(capwap, get_wtp, [list_to_binary(CN)]) of
	{ok, WTP} ->
	    print_wtp(WTP);
	{error, Reason} ->
	    io:format("Error: ~p~n", [Reason]);
	Other ->
	    io:format("Error: ~p~n", [Other])
    end;

main(Opts, ["dp", "wtp", "list"]) ->
    WTPs = rpc(capwap_dp, list_wtp, []),
    Verbose = proplists:get_bool(verbose, Opts),
    [print_dp_wtp(Verbose, WTP) || WTP <- WTPs];

main(Opts, ["dp", "stats"]) ->
    StatsIn = rpc(capwap_dp, get_stats, []),
    [H|_] = StatsIn,
    {_, Totals} =
	lists:foldl(fun(Stats, {Cnt, Sum}) ->
			    S = tuple_to_list(Stats),
			    case proplists:get_bool(verbose, Opts) of
				true ->
				    Label = io_lib:format("Thread ~w", [Cnt]),
				    print_worker_stats(Label, S);
				_  ->
				    ok
			    end,
			    {Cnt + 1, lists:zipwith(fun(X, Y) -> X + Y end, S, Sum)}
		    end,
		    {1, lists:duplicate(size(H), 0)}, StatsIn),
    print_worker_stats("Total", Totals);

main(_, ["station", "list"]) ->
    Stations = rpc(capwap, list_stations, []),
    lists:foreach(fun({{CommonName, {Address, Port}}, MACs}) ->
			  io:format("~s : ~s:~w~n", [CommonName, inet_parse:ntoa(Address), Port]),
			  lists:foreach(fun(Station) -> io:format("  ~s~n", [ieee80211_station:format_mac(Station)]) end, MACs)
		  end, Stations);

main(_, ["station", "detach", MACStr]) ->
    case mac_to_bin(MACStr) of
	MAC when is_binary(MAC) ->
	    R = rpc(capwap, detach_station, [MAC]),
	    io:format("~p~n", [R]);

	_ ->
	    io:format("invalid MAC: '~s'~n", [MACStr])
    end;

main(_, ["update", CommonName, Link, Hash]) ->
    case catch validate_hash(Hash) of
        {ok, BinaryHash} ->
            Res = rpc(capwap_ac, firmware_download, [list_to_binary(CommonName), list_to_binary(Link), BinaryHash]),
            io:format(user, "~p~n", [Res]);
        Error ->
            io:format("catch: ~p~n", [Error])
    end;

main(_, ["set-ssid", CommonName, SSID]) ->
    main(["set-ssid", CommonName, SSID, "1"]);

main(_, ["set-ssid", CommonName, SSID, RadioID]) ->
    Res = rpc(capwap_ac, set_ssid, [list_to_binary(CommonName), list_to_integer(RadioID),
				    list_to_binary(SSID), 0]),
    io:format("~nResult: ~p~n", [Res]);

main(_, ["stop-radio", CommonName, RadioID]) ->
    Res = rpc(capwap_ac, stop_radio, [list_to_binary(CommonName), list_to_integer(RadioID)]),
    io:format("~nResult: ~p~n", [Res]);

main(_, _) ->
    io:format("unknown command or arguments~n"),
    help().

main(Args) ->
    OptSpecList = option_spec_list(),
    case getopt:parse(OptSpecList, Args) of
        {ok, {Options, NonOptArgs}} ->
	    main(Options, NonOptArgs);
        {error, _} ->
	    io:format("unknown command or arguments~n"),
	    help()
    end.

help() ->
    SN = escript:script_name(),
    io:format("Usage: ~s [-v] <commands> <args...>~n~n"
	      "  -v, --verbose                               → verbose output~n~n"
              "CAPWAP commands:~n"
              "  list                                        → list all registered wtps~n"
              "  show <common name>                          → show wtp information~n"
              "  update <common name> <link> <hash>          → update wtp~n"
              "  set-ssid <common name> <SSID> [RadioID]     → set ssid~n"
              "  stop-radio <common name> <RadioID>          → stop wifi radio~n"
              "Station commands:~n"
              "  station list                                → list all known stations~n"
              "  station detach <Station MAC>                → detach station from WLAN~n"
              "Data Path commands:~n"
              "  dp wtp list                                 → list all WTP's with actve data paths~n"
              "  dp stats                                    → show data path statistics~n",
	      [SN]).

rpc(Module, Function, Args) ->
    enit:call("capwap", [{match, true}], Module, Function, Args).

validate_hash(Hash) when length(Hash) == 64 -> {ok, << <<(hex2dec(C)):4>> || C <- Hash >>}.

hex2dec(C) when C >= $a andalso C =< $f -> C - $a + 10;
hex2dec(C) when C >= $A andalso C =< $F -> C - $A + 10;
hex2dec(C) when C >= $0 andalso C =< $9 -> C - $0.

mac_to_bin(MAC) ->
        case io_lib:fread("~16u:~16u:~16u:~16u:~16u:~16u", MAC) of
                {ok, Mlist, []} -> list_to_binary(Mlist);
                _ -> undefined
        end.

fmt_endpoint({IP, Port}) ->
    [fmt_ip(IP), $:, integer_to_list(Port)].

fmt_ip(IP) ->
    case inet:ntoa(IP) of
	S when is_list(S) ->
	    S;
	_ ->
	    io_lib:format("~w", [IP])
    end.

fmt_mac(<<A:8, B:8, C:8, D:8, E:8, F:8>>) ->
    io_lib:format("~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b",
		  [A,B,C,D,E,F]).

fmt_bool(X) when is_atom(X) -> X;
fmt_bool(X) -> X > 0.

fmt_bool(X, _) when is_atom(X) -> X;
fmt_bool(X, {True, _}) when X > 0 -> True;
fmt_bool(_, {_, False}) -> False.

print_wtp_config(#{config := Config}) ->
    io:format("CAPWAP Config Settings:~n"
	      "  Power Save Mode Timeouts, Idle: ~w sec, Busy: ~w sec~n"
	      "  Max Stations: ~w~n"
	      "  Echo Request Interval: ~w sec~n"
	      "  Discovery Interval: ~w sec~n"
	      "  Station Idle Timeout: ~w sec~n"
	      "  Data Channel Dead Interval: ~w sec~n"
	      "  AC Join Timeout: ~w sec~n"
	      "  Admin Password: ~s~n"
	      "  WLAN Hold Time: ~w sec~n",
	      [Config#wtp.psm_idle_timeout, Config#wtp.psm_busy_timeout,
	       Config#wtp.max_stations, Config#wtp.echo_request_interval,
	       Config#wtp.discovery_interval, Config#wtp.idle_timeout,
	       Config#wtp.data_channel_dead_interval, Config#wtp.ac_join_timeout,
	       Config#wtp.admin_pw, Config#wtp.wlan_hold_time]).

print_wtp_radio_wlan_state(#wlan{bss = BSS,
				 state = WlanState}) ->
    io:format("    BSS: ~s~n"
	      "    Running: ~w~n",
	      [fmt_mac(BSS), WlanState]);
print_wtp_radio_wlan_state(_) ->
    io:format("    BSS: unconfigure~n"
	      "    Running: unconfigure~n").

print_wtp_radio_wlan(#wtp_radio{radio_id = RadioId},
		     #wtp_wlan_config{wlan_id = WlanId} = WlanCfg,
		     WlansState) ->
    io:format("  WLAN #~w:~n"
	      "    SSID: ~s~n"
	      "    Hidden SSID: ~w~n"
	      "    Privay: ~w~n",
	      [WlanId, WlanCfg#wtp_wlan_config.ssid,
	       fmt_bool(WlanCfg#wtp_wlan_config.suppress_ssid),
	       fmt_bool(WlanCfg#wtp_wlan_config.privacy, {enabled, disabled})]),
    print_wtp_radio_wlan_state(lists:keyfind({RadioId, WlanId}, 2, WlansState)).

fmt_wtp_radio_oper_mode(#wtp_radio{
			   operation_mode = OperMode,
			   channel = Channel,
			   channel_assessment = CCA,
			   energy_detect_threshold = EDT})
  when OperMode == '802.11b'; OperMode == '802.11g' ->
        io_lib:format("  Operation Mode: ~w~n"
		      "    Channel: ~w~n"
		      "    (*) Channel Assessment Method: ~w~n"
		      "    Energy Detect Threshold: ~w~n",
		      [OperMode, Channel, CCA, EDT]);
fmt_wtp_radio_oper_mode(#wtp_radio{
			   operation_mode = OperMode,
			   channel = Channel,
			   band_support = BandSupport,
			   ti_threshold = TiThresHold})
  when OperMode == '802.11a' ->
    io_lib:format("  Operation Mode: 802.11a~n"
		  "    Channel: ~w~n"
		  "    Band Support: 0x~2.16.0b~n"
		  "    (*) TI Threshold: ~w~n",
		  [Channel, BandSupport, TiThresHold]);
fmt_wtp_radio_oper_mode(#wtp_radio{
			   operation_mode = OperMode,
			   channel = Channel}) ->
    io_lib:format("  Operation Mode: ~s~n"
		  "    Channel: ~w~n",
		  [OperMode, Channel]).

fmt_rate(Rate) when Rate rem 2 == 0 ->
    Rate div 2;
fmt_rate(Rate) ->
    Rate / 2.

fmt_wtp_radio_80211n(_Radio, false) ->
    [];
fmt_wtp_radio_80211n(#wtp_radio{
			a_msdu            = AggMSDU,
			a_mpdu            = AggMPDU,
			deny_non_11n      = DenyNon11n,
			short_gi          = ShortGI,
			bandwidth_binding = BandwidthBinding,
			max_supported_mcs = MaxSupportedMCS,
			max_mandatory_mcs = MaxMandatoryMCS,
			tx_antenna        = RxAntenna,
			rx_antenna        = RxAntenna}, _) ->
    io_lib:format("  802.11n Settings:~n"
		  "    A-MSDU: ~w~n"
		  "    A-MPDU: ~w~n"
		  "    11n Only: ~w~n"
		  "    Short GI: ~w~n"
		  "    Bandwidth Binding Mode: ~s~n"
		  "    Max. supported MCS: ~w~n"
		  "    Max. mandatory MCS: ~w~n"
		  "    TxAntenna Cfg.: ~8.2.0b~n"
		  "    RxAntenna Cfg.: ~8.2.0b~n",
		  [fmt_bool(AggMSDU, {enabled, disabled}),
		   fmt_bool(AggMPDU, {enabled, disabled}),
		   fmt_bool(DenyNon11n),
		   fmt_bool(ShortGI, {enabled, disabled}),
		   fmt_bool(BandwidthBinding, {"20MHz", "40Mhz"}),
		   MaxSupportedMCS,
		   MaxMandatoryMCS, RxAntenna, RxAntenna]).

print_wtp_radio(Radio, WlansState) ->
    io:format("Radio #~w Config:~n"
	      "  Type: ~w~n"
	      "  Supported Rates: ~w (Mbit)~n"
	      "~s"
	      "  Beacon Period: ~w time units (~f ms)~n"
	      "  DTIM Period: ~w~n"
	      "  Short Preamble: ~w~n"
	      "  RTS Threshold: ~w bytes~n"
	      "  Short Retry: ~w~n"
	      "  Long Retry: ~w~n"
	      "  Fragmentation Threshold: ~w bytes~n"
	      "  Tx MSDU Lifetime: ~w time units (~f ms)~n"
	      "  Rx MSDU Lifetime: ~w time units (~f ms)~n"
	      "  Tx Power: ~w dBm~n"
	      "  Diversity: ~w~n"
	      "  Combiner: ~w~n"
	      "  Antenna Selection: ~w~n"
	      "  (*) Report Interval: ~w sec~n"
	      "~s",
	      [Radio#wtp_radio.radio_id, Radio#wtp_radio.radio_type,
	       [fmt_rate(R) || R <- Radio#wtp_radio.supported_rates],
	       fmt_wtp_radio_oper_mode(Radio),
	       Radio#wtp_radio.beacon_interval, Radio#wtp_radio.beacon_interval * 1.024,
	       Radio#wtp_radio.dtim_period, Radio#wtp_radio.short_preamble,
	       Radio#wtp_radio.rts_threshold, Radio#wtp_radio.short_retry,
	       Radio#wtp_radio.long_retry, Radio#wtp_radio.fragmentation_threshold,
	       Radio#wtp_radio.tx_msdu_lifetime, Radio#wtp_radio.tx_msdu_lifetime * 1.024,
	       Radio#wtp_radio.rx_msdu_lifetime, Radio#wtp_radio.rx_msdu_lifetime * 1.024,
	       Radio#wtp_radio.tx_power, Radio#wtp_radio.diversity,
	       Radio#wtp_radio.combiner, Radio#wtp_radio.antenna_selection,
	       Radio#wtp_radio.report_interval,
	       fmt_wtp_radio_80211n(Radio, proplists:get_bool('802.11n', Radio#wtp_radio.radio_type))]),
    [print_wtp_radio_wlan(Radio, Wlan, WlansState) || Wlan <- Radio#wtp_radio.wlans].

print_wtp_radios(#{config :=
		       #wtp{radios = Radios},
		   wlans := Wlans}) ->
    [print_wtp_radio(Radio, Wlans) || Radio <- Radios].

format_wtp_board_data_sub_element({0, Value}) ->
    io_lib:format("      Model:      ~s", [Value]);
format_wtp_board_data_sub_element({1, Value}) ->
    io_lib:format("      Serial:     ~s", [Value]);
format_wtp_board_data_sub_element({2, Value}) ->
    io_lib:format("      Board Id:   ~s", [Value]);
format_wtp_board_data_sub_element({3, Value}) ->
    io_lib:format("      Board Rev.: ~s", [Value]);
format_wtp_board_data_sub_element({4, Value})
  when is_binary(Value), size(Value) == 6 ->
    ["      Base MAC:   ", fmt_mac(Value)];
format_wtp_board_data_sub_element({4, Value}) ->
    io_lib:format("      Base MAC:   ~w", [Value]);
format_wtp_board_data_sub_element({Id, Value}) ->
    io_lib:format("      ~w: ~s (~w)", [Id, Value, Value]).

vendor_id_str(18681) -> "Travelping GmbH";
vendor_id_str(31496) -> "NetModule AG";
vendor_id_str(Id) -> integer_to_list(Id).

format_wtp_board_data(#wtp_board_data{
			 vendor = Vendor,
			 board_data_sub_elements = SubElements}) ->
    FmtSub = lists:map(fun format_wtp_board_data_sub_element/1, SubElements),
    io_lib:format("    Vendor: ~8.16.0B (~s)~n"
		  "    Sub Elements:~n~s",
		  [Vendor, vendor_id_str(Vendor), string:join(FmtSub, "\n")]);
format_wtp_board_data(BoardData) ->
    io_lib:format("    undecoded: ~w", [BoardData]).

format_wtp_descriptor_sub_element({{0, 0}, Value}) ->
    io_lib:format("      Hardware Version: ~s", [Value]);
format_wtp_descriptor_sub_element({{0, 1}, Value}) ->
    io_lib:format("      Software Version: ~s", [Value]);
format_wtp_descriptor_sub_element({{0, 2}, Value}) ->
    io_lib:format("      Boot Version:     ~s", [Value]);
format_wtp_descriptor_sub_element({{0, 3}, Value}) ->
    io_lib:format("      Other Version:    ~s", [Value]);
format_wtp_descriptor_sub_element({{Vendor, Id}, Value}) ->
    io_lib:format("      ~w:~w: ~s (~w)", [Vendor, Id, Value, Value]).

format_wtp_descriptor(#wtp_descriptor{
			 max_radios = MaxRadios,
			 radios_in_use = RadiosInUse,
			 encryption_sub_element = EncSubElem,
			 sub_elements = SubElements}) ->
    FmtSub = lists:map(fun format_wtp_descriptor_sub_element/1, SubElements),
    io_lib:format("    max Radios: ~w~n"
		  "    Radios in use: ~w~n"
		  "    Encryption Sub Element: ~w~n"
		  "    Sub Elements:~n~s",
		  [MaxRadios, RadiosInUse, EncSubElem,
		   string:join(FmtSub, "\n")]);
format_wtp_descriptor(Descriptor) ->
    io_lib:format("    undecoded: ~w", [Descriptor]).

fmt_time_ms(StartTime) ->
    MegaSecs = StartTime div 1000000000,
    Rem1 = StartTime rem 1000000000,
    Secs = Rem1 div 1000,
    MilliSecs = StartTime rem 1000,
    {{Year, Month, Day}, {Hour, Minute, Second}} =
	calendar:now_to_universal_time({MegaSecs, Secs, MilliSecs * 1000}),
    io_lib:format("~4.10.0b-~2.10.0b-~2.10.0b ~2.10.0b:~2.10.0b:~2.10.0b.~4.10.0b",
		  [Year, Month, Day, Hour, Minute, Second, MilliSecs]).

print_wtp(#{id := Id,
	    station_count := StationCnt,
	    location := Location,
	    board_data := BoardData,
	    descriptor := Descriptor,
	    name := Name,
	    start_time := StartTime,
	    ctrl_channel_address := CtrlAddress,
	    data_channel_address := DataAddress,
	    session_id := SessionId,
	    mac_mode := MacMode,
	    tunnel_mode := TunnelMode,
	    echo_request_timeout := EchoReqTimeout
	   } = WTP) ->
    Now = erlang:system_time(milli_seconds),
    io:format("WTP: ~s, ~w Stations~n"
	      "  Start Time: ~s (~.4f seconds ago)~n"
	      "  Location: ~s~n"
	      "  Board Data:~n~s~n"
	      "  Descriptor:~n~s~n"
	      "  Name: ~s~n"
	      "  Control Channel Endpoint: ~s~n"
	      "  Data Channel Endpoint: ~s~n"
	      "  Session Id: ~32.16.0b~n"
	      "  MAC Mode: ~s~n"
	      "  Tunnel Mode: ~s~n"
	      "  Echo Request Timeout: ~w sec~n",
	      [Id, StationCnt, fmt_time_ms(StartTime), (Now - StartTime) / 1000,
	       Location, format_wtp_board_data(BoardData),
	       format_wtp_descriptor(Descriptor), Name,
	       fmt_endpoint(CtrlAddress), fmt_endpoint(DataAddress),
	       SessionId, MacMode, TunnelMode, EchoReqTimeout]),
    print_wtp_config(WTP),
    print_wtp_radios(WTP).

print_worker_stats(Label, [RcvdPkts, SendPkts, RcvdBytes, SendBytes,
			   RcvdFragments, SendFragments,
			   ErrInvalidStation, ErrFragmentInvalid, ErrFragmentTooOld,
			   ErrInvalidWtp, ErrHdrLengthInvalid, ErrTooShort,
			   RateLimitUnknownWtp]) ->
    io:format("~s:~n"
	      "  Input:  #bytes: ~20.w, #pkts: ~10.w, #fragments: ~10.w~n"
	      "  Output: #bytes: ~20.w, #pkts: ~10.w, #fragments: ~10.w~n"
	      "  Errors: #Invalid Station:    ~7.w, #Invalid WTP:        ~7.w~n"
	      "          #Fragment Invalid:   ~7.w, #Fragment Too Old:   ~7.w~n"
	      "          #Header Length:      ~7.w, #Pkt Too Short:      ~7.w~n"
	      "          #Rate Limit new WTP: ~7.w~n",
	      [Label,
	       RcvdBytes, RcvdPkts, RcvdFragments,
	       SendBytes, SendPkts, SendFragments,
	       ErrInvalidStation,   ErrInvalidWtp,
	       ErrFragmentInvalid,  ErrFragmentTooOld,
	       ErrHdrLengthInvalid, ErrTooShort,
	       RateLimitUnknownWtp]).

print_dp_wtp(Verbose, {{Address, Port}, _WLANs, STAs, _RefCnt, _MTU, Stats}) ->
    io:format("~s:~w~n", [inet_parse:ntoa(Address), Port]),
    print_dp_wtp_stats(Verbose, Stats),
    print_dp_wtp_stas(Verbose, STAs).

print_dp_wtp_stats(false, _) ->
    ok;
print_dp_wtp_stats(_, {RcvdPkts, SendPkts, RcvdBytes, SendBytes,
		       RcvdFragments, SendFragments,
		       ErrInvalidStation, ErrFragmentInvalid, ErrFragmentTooOld}) ->
    io:format("  Input:  #bytes: ~20.w, #pkts: ~10.w, #fragments: ~10.w~n"
	      "  Output: #bytes: ~20.w, #pkts: ~10.w, #fragments: ~10.w~n"
	      "  Errors: #Invalid Station:    ~7.w,~n"
	      "          #Fragment Invalid:   ~7.w, #Fragment Too Old:   ~7.w~n",
	      [RcvdBytes, RcvdPkts, RcvdFragments,
	       SendBytes, SendPkts, SendFragments,
	       ErrInvalidStation,
	       ErrFragmentInvalid, ErrFragmentTooOld]).

print_dp_wtp_stas(_, []) ->
    ok;
print_dp_wtp_stas(false, [{MAC, _RadioId, _BSS, _Stats}|STAs]) ->
    io:format("  ~s~n", [ieee80211_station:format_mac(MAC)]),
    print_dp_wtp_stas(false, STAs);
print_dp_wtp_stas(true, [{MAC, _RadioId, _BSS, Stats}|STAs]) ->
    {RcvdPkts, SendPkts, RcvdBytes, SendBytes} = Stats,
    io:format("  ~s, In:  #bytes: ~20.w, #pkts: ~10.w, Out: #bytes: ~20.w, #pkts: ~10.w~n",
	      [ieee80211_station:format_mac(MAC), RcvdBytes, RcvdPkts, SendBytes, SendPkts]),
    print_dp_wtp_stas(true, STAs).

option_spec_list() ->
    [
     %% {Name,     ShortOpt,  LongOpt,       ArgSpec,               HelpMsg}
     {help,        $h,        "help",        undefined,             "Show the program options"},
     {verbose,     $v,        "verbose",     undefined,             "Verbose output"}
    ].
