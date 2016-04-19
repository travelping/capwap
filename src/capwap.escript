#!/usr/bin/env escript
%%! -hidden -connect_all false -smp disable -kernel inet_dist_use_interface {127,0,0,1}
-mode(compile).

-include_lib("capwap/include/capwap_config.hrl").

main(_, []) ->
    help();

main(_, ["list"]) ->
    WTPs = rpc(capwap, list_wtps, []),
    [io:format("~s : ~s:~w~n", [CommonName, inet_parse:ntoa(Address), Port]) || {CommonName, {Address, Port}} <- WTPs];

main(_, ["show", CN]) ->
    WTP = rpc(capwap, get_wtp, [list_to_binary(CN)]),
    print_wtp(WTP);

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

print_wtp_radio_wlan(#wtp_radio{radio_id = RadioId},
		     #wtp_wlan{wlan_id = WlanId} = Wlan,
		     WlansState) ->

    WlanState = case lists:keyfind({RadioId, WlanId}, 2, WlansState) of
		    S when is_tuple(S) ->
			%% TODO: accessing the wlan state record like this is a
			%%       hack, will be replaced soonish
			element(3, S);
		    Other ->
			Other
		end,
    io:format("WLAN #~w:~n"
	      "  SSID: ~s~n"
	      "  Hidden SSID: ~w~n"
	      "  Running: ~w~n",
	      [WlanId, Wlan#wtp_wlan.ssid, Wlan#wtp_wlan.suppress_ssid, WlanState]).

print_wtp_radio(Radio, WlansState) ->
    io:format("Radio #~w Config:~n"
	      "  Type: ~w~n"
	      "  Operation Mode: ~w~n"
	      "  Channel: ~w~n"
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
	      "  (*) Channel Assessment Method: ~w~n"
	      "  Energy Detect Threshold: ~w~n"
	      "  Band Support: 0x~2.16.0b~n"
	      "  (*) TI Threshold: ~w~n"
	      "  Diversity: ~w~n"
	      "  Combiner: ~w~n"
	      "  Antenna Selection: ~w~n"
	      "  (*) Report Interval: ~w sec~n",
	      [Radio#wtp_radio.radio_id, Radio#wtp_radio.radio_type,
	       Radio#wtp_radio.operation_mode, Radio#wtp_radio.channel,
	       Radio#wtp_radio.beacon_interval, Radio#wtp_radio.beacon_interval * 1.024,
	       Radio#wtp_radio.dtim_period, Radio#wtp_radio.short_preamble,
	       Radio#wtp_radio.rts_threshold, Radio#wtp_radio.short_retry,
	       Radio#wtp_radio.long_retry, Radio#wtp_radio.fragmentation_threshold,
	       Radio#wtp_radio.tx_msdu_lifetime, Radio#wtp_radio.tx_msdu_lifetime * 1.024,
	       Radio#wtp_radio.rx_msdu_lifetime, Radio#wtp_radio.rx_msdu_lifetime * 1.024,
	       Radio#wtp_radio.tx_power, Radio#wtp_radio.channel_assessment,
	       Radio#wtp_radio.energy_detect_threshold, Radio#wtp_radio.band_support,
	       Radio#wtp_radio.ti_threshold, Radio#wtp_radio.diversity,
	       Radio#wtp_radio.combiner, Radio#wtp_radio.antenna_selection,
	       Radio#wtp_radio.report_interval]),
    [print_wtp_radio_wlan(Radio, Wlan, WlansState) || Wlan <- Radio#wtp_radio.wlans].

print_wtp_radios(#{config :=
		       #wtp{radios = Radios},
		   wlans := Wlans}) ->
    [print_wtp_radio(Radio, Wlans) || Radio <- Radios].

print_wtp({ok, #{id := Id,
		 station_count := StationCnt,
		 version := Version,
		 ctrl_channel_address := CtrlAddress,
		 data_channel_address := DataAddress,
		 session_id := SessionId,
		 mac_mode := MacMode,
		 tunnel_mode := TunnelMode,
		 echo_request_timeout := EchoReqTimeout
		} = WTP}) ->
    io:format("WTP: ~s, ~w Stations~n"
	      "  Version: ~w~n"
	      "  Control Channel Endpoint: ~s~n"
	      "  Data Channel Endpoint: ~s~n"
	      "  Session Id: ~32.16.0b~n"
	      "  MAC Mode: ~s~n"
	      "  Tunnel Mode: ~s~n"
	      "  Echo Request Timeout: ~w sec~n",
	      [Id, StationCnt, Version,
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

print_dp_wtp(Verbose, {{Address, Port}, STAs, _RefCnt, _MTU, Stats}) ->
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
print_dp_wtp_stas(false, [{MAC, _Stats}|STAs]) ->
    io:format("  ~s~n", [ieee80211_station:format_mac(MAC)]),
    print_dp_wtp_stas(false, STAs);
print_dp_wtp_stas(true, [{MAC, Stats}|STAs]) ->
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
