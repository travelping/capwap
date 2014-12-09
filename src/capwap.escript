#!/usr/bin/env escript
%%! -hidden -connect_all false -smp disable -kernel inet_dist_use_interface {127,0,0,1}
-mode(compile).

main([]) ->
    help();

main(["list"]) ->
    WTPs = rpc(capwap, list_wtps, []),
    [io:format("~s : ~s:~w~n", [CommonName, inet_parse:ntoa(Address), Port]) || {CommonName, {Address, Port}} <- WTPs];

main(["station", "list"]) ->
    Stations = rpc(capwap, list_stations, []),
    lists:foreach(fun({{CommonName, {Address, Port}}, MACs}) ->
			  io:format("~s : ~s:~w~n", [CommonName, inet_parse:ntoa(Address), Port]),
			  lists:foreach(fun(Station) -> io:format("  ~s~n", [ieee80211_station:format_mac(Station)]) end, MACs)
		  end, Stations);

main(["station", "detach", MACStr]) ->
    case mac_to_bin(MACStr) of
	MAC when is_binary(MAC) ->
	    R = rpc(capwap, detach_station, [MAC]),
	    io:format("~p~n", [R]);

	_ ->
	    io:format("invalid MAC: '~s'~n", [MACStr])
    end;

main(["update", CommonName, Link, Hash]) ->
    case catch validate_hash(Hash) of
        {ok, BinaryHash} ->
            Res = rpc(capwap_ac, firmware_download, [list_to_binary(CommonName), list_to_binary(Link), BinaryHash]),
            io:format(user, "~p~n", [Res]);
        Error ->
            io:format("catch: ~p~n", [Error])
    end;

main(["set-ssid", CommonName, SSID]) ->
    main(["set-ssid", CommonName, SSID, "1"]);

main(["set-ssid", CommonName, SSID, RadioID]) ->
    Res = rpc(capwap_ac, set_ssid, [list_to_binary(CommonName), list_to_binary(SSID), list_to_integer(RadioID)]),
    io:format("~nResult: ~p~n", [Res]);

main(["stop-radio", CommonName, RadioID]) ->
    Res = rpc(capwap_ac, stop_radio, [list_to_binary(CommonName), list_to_integer(RadioID)]),
    io:format("~nResult: ~p~n", [Res]);

main(_) ->
    io:format("unknown command or arguments~n"),
    help().

help() ->
    SN = escript:script_name(),
    io:format("Usage: ~s <command> <args...>~n"
              "WTP commands:~n"
              "  list                                        → list all registered wtps~n"
              "  update <common name> <link> <hash>          → update wtp~n"
              "  set-ssid <common name> <SSID> [RadioID]     → set ssid~n"
              "  stop-radio <common name> <RadioID>          → stop wifi radio~n"
              "Station commands:~n"
              "  station list                                → list all known stations~n"
              "  station detach <Station MAC>                → detach station from WLAN~n",
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
