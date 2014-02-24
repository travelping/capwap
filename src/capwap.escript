#!/usr/bin/env escript
%%! -hidden -connect_all false -smp disable -kernel inet_dist_use_interface {127,0,0,1}
-mode(compile).

main([]) ->
    help();

main(["list"]) ->
    [io:format("~s : ~s~n", [CommonName, inet_parse:ntoa(Address)]) || {CommonName, Address} <- rpc(capwap_wtp_reg, list_commonnames, [])];

main(["update", CommonName, Link, Hash]) ->
    case catch validate_hash(Hash) of
        {ok, BinaryHash} ->
            Res = rpc(capwap_ac, firmware_download, [list_to_binary(CommonName), list_to_binary(Link), Hash]),
            io:format(user, "~p~n", [Res]);
        Error ->
            io:format("catch: ~p~n", [Error])
    end;

main(_) ->
    io:format("unknown command or arguments~n"),
    help().

help() ->
    SN = escript:script_name(),
    io:format("Usage: ~s <command> <args...>~n"
              "Commands:~n"
              "  list                               → list all registered wtps~n"
              "  update <common name> <link> <hash> → update wtp~n", [SN]).

rpc(Module, Function, Args) ->
    enit:call("capwap", [{match, true}], Module, Function, Args).

validate_hash(Hash) when length(Hash) == 64 -> {ok, << <<(hex2dec(C)):4>> || C <- Hash >>}.

hex2dec(C) when C >= $a andalso C =< $f -> C - $a + 10;
hex2dec(C) when C >= $A andalso C =< $F -> C - $A + 10;
hex2dec(C) when C >= $0 andalso C =< $9 -> C - $0.
