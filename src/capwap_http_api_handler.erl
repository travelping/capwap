%% Copyright (C) 2013-2023, Travelping GmbH <info@travelping.com>

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

-module(capwap_http_api_handler).

-include("../include/capwap_packet.hrl").
-include("../include/capwap_config.hrl").
-include("../include/capwap_ac.hrl").

-export([init/2, content_types_provided/2,
         handle_request_json/2,
         handle_request_text/2,
         allowed_methods/2,
         content_types_accepted/2,fmt_dp_wtp/2]).

-record(s, {
    verbose = false :: boolean(),
    opts
}).

init(Req, Opts) ->
    Verbose = cowboy_req:header(<<"verbose">>, Req, <<"false">>),
    {cowboy_rest, Req, #s{verbose = (Verbose == <<"true">>), opts = Opts}}.

allowed_methods(Req, State) ->
    {[<<"GET">>, <<"DELETE">>, <<"POST">>], Req, State}.

content_types_provided(Req, State) ->
    {[
      {<<"application/json">>, handle_request_json},
      {{<<"text">>, <<"plain">>, '*'},  handle_request_text}
     ], Req, State}.

content_types_accepted(Req, State) ->
    {[{'*', handle_request_json}], Req, State}.

handle_request_json(Req, State) ->
    Path = binary:split(cowboy_req:path(Req), <<"/">>, [global, trim_all]),
    Method = cowboy_req:method(Req),
    case Path of
        [<<"api">>, <<"v1">>, <<"wtp">> | TailPath] ->
            handle_request_wtp(Method, TailPath, Req, State);
        [<<"api">>, <<"v1">>, <<"dp">> | TailPath] ->
            handle_request_dp(Method, TailPath, Req, State);
        [<<"api">>, <<"v1">>, <<"station">> | TailPath] ->
            handle_request_station(Method, TailPath, Req, State);
        [<<"api">>, <<"v1">>, <<"version">> ] ->
            case Method of
                <<"GET">> ->
                    {get_release_vsn(), Req, State};
                _ ->
                    {jsx:encode([{error, bad_command}]), Req, State}
            end;
        [<<"metrics">> | TailPath] ->
            TailPath1 = [ binary_to_existing_atom(P, utf8) || P <- TailPath ],
            handle_request_metrics(json, TailPath1, Req, State);
        _ ->
            {jsx:encode([{error, bad_command}]), Req, State}
    end.

handle_request_text(Req, State) ->
    Path = binary:split(cowboy_req:path(Req), <<"/">>, [global, trim_all]),
    Method = cowboy_req:method(Req),
    case {Method, Path} of
        {<<"GET">>, [<<"metrics">> | TailPath] } ->
            TailPath1 = [ binary_to_existing_atom(P, utf8) || P <- TailPath ],
            handle_request_metrics(text, TailPath1, Req, State);
        _ ->
            {<<"error: bad_command">>, Req, State}
    end.

handle_request_wtp(<<"GET">>, [], Req, State) ->
    WTPs = [format_wtp(WTP) || WTP = {_, E} <- capwap:list_wtps(), E =/= undefined],
    {jsx:encode(WTPs), Req, State};
handle_request_wtp(<<"GET">>, [ _ ], Req, State) ->
    CN = cowboy_req:binding(id, Req),
    case capwap:get_wtp(CN) of
        {error, Error} ->
            {jsx:encode([{error, Error}]), Req, State};
        {ok, #{id              := Id,
          station_count        := StationCnt,
          location             := Location,
          board_data           := BoardData,
          descriptor           := Descriptor,
          name                 := Name,
          start_time           := StartTime,
          ctrl_channel_address := CtrlAddress,
          data_channel_address := DataAddress,
          session_id           := SessionId,
          echo_request_timeout := EchoReqTimeout}} ->
            Now = erlang:system_time(milli_seconds),
            Ret = [{id, Id}, {stations, StationCnt},
                   {start_time, [{time, fmt_time_ms(StartTime)},
                                 {duration, (Now - StartTime) / 1000}]},
                   {location, Location}, {name, Name},
                   {board_data, fmt_wtp_board_data(BoardData)},
                   {descriptor, fmt_wtp_descriptor(Descriptor)},
                   {control_channel_endpoint, fmt_endpoint(CtrlAddress)},
                   {data_channel_endpoint, fmt_endpoint(DataAddress)},
                   {session_id, bin_fmt(SessionId)},
                   {echo_request_timeout, EchoReqTimeout}],
            {jsx:encode(Ret), Req, State}
    end;
handle_request_wtp(<<"POST">>, [_, <<"update">> | _], Req, State) ->
    CommonName= cowboy_req:binding(id, Req),
    Link = cowboy_req:binding(link, Req),
    Hash = cowboy_req:binding(hash, Req),
    case catch validate_hash(Hash) of
        {ok, BinaryHash} ->
            Res = capwap_ac:firmware_download(CommonName, Link, BinaryHash),
            {jsx:encode([{user, Res}]), Req, State};
        Error ->
            {jsx:encode([{error, bin_fmt("~p", [Error])}]), Req, State}
    end;
handle_request_wtp(<<"POST">>, [_, <<"set-ssid">> | _], Req, State) ->
    CommonName = cowboy_req:binding(id, Req),
    SSID = cowboy_req:binding(ssid, Req),
    try
        RadioID = binary_to_integer(cowboy_req:binding(rid, Req, <<"1">>)),
        case capwap_ac:set_ssid(CommonName, RadioID, SSID, 0) of
            {error, Reason} ->
                {jsx:encode([{error, bin_fmt(Reason)}]), Req, State};
            Other ->
                {jsx:encode([{setup, bin_fmt(Other)}]), Req, State}
        end
    catch
        _:badarg ->
            {jsx:encode([{error, badarg}]), Req, State}
    end;
handle_request_wtp(<<"DELETE">>, [_, <<"stop-radio">> | _], Req, State) ->
    CN = cowboy_req:binding(id, Req),
    try
        RadioID = erlang:binary_to_integer(cowboy_req:binding(rid, Req)),
        Res = capwap_ac:stop_radio(CN, RadioID),
        {jsx:encode([{res, Res}]), Req, State}
    catch
        _:badarg ->
            {jsx:encode([{error, badarg}]), Req, State}
    end;
handle_request_wtp(_, _, Req, State) ->
    {jsx:encode([{error, bad_command}]), Req, State}.

handle_request_station(<<"GET">>, [], Req, State) ->
    Stations = capwap:list_stations(),
    Ret = lists:map(fun({{CommonName, Endpoint}, MACs}) ->
        [{id, CommonName},
         {address, fmt_endpoint(Endpoint)},
         {macs, [ fmt_station_mac(Station) || Station <- MACs ]}]
    end, Stations),
    {jsx:encode(Ret), Req, State};
handle_request_station(<<"DELETE">>, [_], Req, State) ->
    MACStr = cowboy_req:binding(id, Req),
    case mac_to_bin(MACStr) of
        MAC when is_binary(MAC) ->
            R = capwap:detach_station(MAC),
            {jsx:encode([{result, R}]), Req, State};
        _ ->
            {jsx:encode([{error, invalid_mac}]), Req, State}
    end;
handle_request_station(_, _, Req, State) ->
    {jsx:encode([{error, bad_command}]), Req, State}.

handle_request_dp(<<"GET">>, [<<"wtp-list">>], Req,
                  State = #s{verbose = Verbose}) ->
    case catch capwap_dp:list_wtp() of
        WTPs when is_list(WTPs) ->
            Res = [fmt_dp_wtp(Verbose, WTP) || WTP <- WTPs],
            {jsx:encode(Res), Req, State};
        _ ->
            {stop, dp_error_response(Req), State}
    end;
handle_request_dp(<<"GET">>, [<<"stats">>], Req,
                  State = #s{verbose = Verbose}) ->
    case catch capwap_dp:get_stats() of
        [H | _] = StatsIn ->
            {_, Totals, Res} = lists:foldl(fun(Stats, {Cnt, Sum, Acc}) ->
                S = tuple_to_list(Stats),
                NewAcc = case Verbose of
                    true ->
                        Label = bin_fmt("thread_~w", [Cnt]),
                        fmt_worker_stats(Label, S, Acc);
                    _  ->
                        Acc
                end,
                {Cnt + 1, lists:zipwith(fun(X, Y) -> X + Y end, S, Sum), NewAcc}
            end, {1, lists:duplicate(size(H), 0), []}, StatsIn),
            Res1 = fmt_worker_stats(<<"total">>, Totals, Res),
            {jsx:encode(Res1), Req, State};
        _ ->
            {stop, dp_error_response(Req), State}
        end;
handle_request_dp(_, _, Req, State) ->
    {jsx:encode([{error, bad_command}]), Req, State}.

handle_request_metrics(text, Path, Req, State) ->
    Metrics = lists:foldl(fun exo_entry_to_list/2, [],
                          exometer:find_entries(Path)),
    {prometheus_encode(Metrics), Req, State};
handle_request_metrics(json, Path, Req, State) ->
    Entries = lists:foldl(fun exo_entry_to_map/2, #{},
                          exometer:find_entries(Path)),
    Metrics = lists:foldl(fun(M, A) ->
                                  maps:get(ioize(M), A) end, Entries,
                          Path),
    {jsx:encode(Metrics), Req, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
get_release_vsn() ->
    Releases = release_handler:which_releases(),
    Vsn = case lists:keyfind("ergw-capwap-node", 1, Releases) of
        false -> "none";
        {_, Version, _, _} -> Version
    end,
    jsx:encode([{version, list_to_binary(Vsn)}]).

format_wtp({Id, Endpoint}) ->
    [{id, Id}, {endpoint, fmt_endpoint(Endpoint)}].

validate_hash(Hash) when length(Hash) == 64 ->
    {ok, << <<(hex2dec(C)):4>> || C <- Hash >>}.

hex2dec(C) when C >= $a andalso C =< $f -> C - $a + 10;
hex2dec(C) when C >= $A andalso C =< $F -> C - $A + 10;
hex2dec(C) when C >= $0 andalso C =< $9 -> C - $0.

mac_to_bin(MAC) ->
    case io_lib:fread("~16u:~16u:~16u:~16u:~16u:~16u", MAC) of
        {ok, Mlist, []} -> list_to_binary(Mlist);
        _ -> undefined
    end.

fmt_dp_wtp(Verbose, {Endpoint, _WLANs, STAs, _RefCnt, _MTU, Stats}) ->
    Res = [{address, fmt_endpoint(Endpoint)}],
    Res1 = fmt_dp_wtp_stats(Verbose, Stats, Res),
    WTP_Stats = lists:map(fun(STA) ->
        fmt_dp_wtp_stas(Verbose, STA)
    end, STAs),
    [{wtp_stats, WTP_Stats} | Res1].

fmt_dp_wtp_stats(true, {RcvdPkts, SendPkts, RcvdBytes, SendBytes,
		       RcvdFragments, SendFragments,
		       ErrInvalidStation, ErrFragmentInvalid, ErrFragmentTooOld}, Acc) ->
    [{input, [{bytes, RcvdBytes},
              {packets, RcvdPkts},
              {fragments, RcvdFragments}]},
     {output, [{bytes, SendBytes},
               {packets, SendPkts},
               {fragments, SendFragments}]},
     {errors, [{invalid_station, ErrInvalidStation},
               {fragment_invalid, ErrFragmentInvalid},
               {fragment_too_old, ErrFragmentTooOld}]} | Acc];
fmt_dp_wtp_stats(_, _, Acc) -> Acc.

fmt_dp_wtp_stas(false, {MAC, _VLAN, _RadioId, _BSSId, _Stats}) ->
    [{mac, list_to_binary(capwap_tools:format_eui(MAC))}];
fmt_dp_wtp_stas(true, {MAC, _VLAN, _RadioId, _BSSId, Stats}) ->
    {RcvdPkts, SendPkts, RcvdBytes, SendBytes} = Stats,
    [{mac, list_to_binary(capwap_tools:format_eui(MAC))},
     {input, [{bytes, RcvdBytes},
              {packets, RcvdPkts}]},
     {output, [{bytes, SendBytes},
               {packets, SendPkts}]}
    ].

fmt_worker_stats(Label, [RcvdPkts, SendPkts, RcvdBytes, SendBytes,
			   RcvdFragments, SendFragments,
			   ErrInvalidStation, ErrFragmentInvalid, ErrFragmentTooOld,
			   ErrInvalidWtp, ErrHdrLengthInvalid, ErrTooShort,
			   RateLimitUnknownWtp], Acc) ->
    [{Label,
         [{input, [{bytes, RcvdBytes},
                   {packets, RcvdPkts},
                   {fragments, RcvdFragments}]},
          {output, [{bytes, SendBytes},
                    {packets, SendPkts},
                    {fragments, SendFragments}]},
          {errors, [{invalid_station, ErrInvalidStation},
                    {invalid_wtp, ErrInvalidWtp},
                    {fragment_invalid, ErrFragmentInvalid},
                    {fragment_too_old, ErrFragmentTooOld},
                    {header_length, ErrHdrLengthInvalid},
                    {pkt_too_short, ErrTooShort},
                    {rate_limit_unknown_wtp, RateLimitUnknownWtp}]}
         ]} | Acc].

fmt_time_ms(StartTime) ->
    MegaSecs = StartTime div 1000000000,
    Rem1 = StartTime rem 1000000000,
    Secs = Rem1 div 1000,
    MilliSecs = StartTime rem 1000,
    {{Year, Month, Day}, {Hour, Minute, Second}} =
	calendar:now_to_universal_time({MegaSecs, Secs, MilliSecs * 1000}),
    bin_fmt("~4.10.0b-~2.10.0b-~2.10.0b ~2.10.0b:~2.10.0b:~2.10.0b.~4.10.0b",
		  [Year, Month, Day, Hour, Minute, Second, MilliSecs]).

fmt_wtp_board_data(#wtp_board_data{
			 vendor = Vendor,
			 board_data_sub_elements = SubElements}) ->
    lists:map(fun fmt_wtp_board_data_sub_element/1, SubElements) ++
        [{vendor, bin_fmt("~8.16.0B", [Vendor])},
         {vendor_id, vendor_id_str(Vendor)}];
fmt_wtp_board_data(BoardData) ->
    {undecoded, bin_fmt(BoardData)}.

fmt_wtp_board_data_sub_element({0, Value}) ->
    {model, Value};
fmt_wtp_board_data_sub_element({1, Value}) ->
    {serial, Value};
fmt_wtp_board_data_sub_element({2, Value}) ->
    {board_id, Value};
fmt_wtp_board_data_sub_element({3, Value}) ->
    {board_revision, Value};
fmt_wtp_board_data_sub_element({4, Value})
  when is_binary(Value), size(Value) == 6 ->
    {base_mac, capwap_tools:format_eui(Value)};
fmt_wtp_board_data_sub_element({4, Value}) ->
    {base_mac, Value};
fmt_wtp_board_data_sub_element({Id, Value}) ->
    {Id, Value}.

vendor_id_str(18681) -> <<"Travelping GmbH">>;
vendor_id_str(31496) -> <<"NetModule AG">>;
vendor_id_str(Id) -> Id.

fmt_endpoint({IP, Port}) ->
    [{ip, fmt_ip(IP)}, {port, Port}].

fmt_ip(IP) ->
    Res = case inet:ntoa(IP) of
        S when is_list(S) ->
            S;
        _ ->
            io_lib:format("~w", [IP])
    end,
    erlang:list_to_binary(Res).

fmt_wtp_descriptor(#wtp_descriptor{
			 max_radios = MaxRadios,
			 radios_in_use = RadiosInUse,
			 encryption_sub_element = EncSubElem,
			 sub_elements = SubElements}) ->
    lists:map(fun fmt_wtp_descriptor_sub_element/1, SubElements) ++
    [ {max_radios, MaxRadios},
      {radios_in_use, RadiosInUse},
      {encription_sub_element, bin_fmt("~ts", [EncSubElem])} ];
fmt_wtp_descriptor(Descriptor) ->
    [{undecoded, bin_fmt(Descriptor)}].

fmt_wtp_descriptor_sub_element({{0, 0}, Value}) ->
    {hardware_version, Value};
fmt_wtp_descriptor_sub_element({{0, 1}, Value}) ->
    {software_version, Value};
fmt_wtp_descriptor_sub_element({{0, 2}, Value}) ->
    {boot_version, Value};
fmt_wtp_descriptor_sub_element({{0, 3}, Value}) ->
    {other_version, Value};
fmt_wtp_descriptor_sub_element({{Vendor, Id}, Value}) ->
    {bin_fmt("~w ~w", [Vendor, Id]), Value}.

bin_fmt(Arg) -> bin_fmt("~w", [Arg]).
bin_fmt(FmtStr, Args) ->
    erlang:list_to_binary(io_lib:format(FmtStr, Args)).

fmt_station_mac(Station) ->
    bin_fmt("~s", [capwap_tools:format_eui(Station)]).

prometheus_encode(Metrics) ->
    lists:foldl(fun prometheus_encode/2, [], Metrics).

prometheus_encode({Path, Type, DataPoints}, Acc) ->
    Name = make_metric_name(Path),
    Payload = [[<<"# TYPE ">>, Name, <<" ">>, map_type(Type), <<"\n">>] |
               [[Name, map_datapoint(DPName), <<" ">>, ioize(Value), <<"\n">>]
                || {DPName, Value} <- DataPoints, is_valid_datapoint(DPName)]],
    Payload1 = maybe_add_sum(Name, DataPoints, Type, Payload),
    [Payload1, <<"\n">> | Acc].

exo_get_value(Name, Fun, AccIn) ->
    case exometer:get_value(Name) of
	{ok, Value} ->
	    Fun(Value, AccIn);
	{error,not_found} ->
	    AccIn
    end.

exo_entry_to_map({Name, Type, enabled}, Metrics) ->
    exo_entry_to_map(Name, {Name, Type}, Metrics).

exo_entry_to_map([Path], {Name, Type}, Metrics) ->
    exo_get_value(Name, fun(V, Acc) ->
				Entry = maps:from_list(V),
				Acc#{ioize(Path) => Entry#{type => Type}}
			end, Metrics);
exo_entry_to_map([H|T], Metric, Metrics) ->
    Key = ioize(H),
    Entry = maps:get(Key, Metrics, #{}),
    Metrics#{Key => exo_entry_to_map(T, Metric, Entry)}.

exo_entry_to_list({Name, Type, enabled}, Metrics) ->
exo_get_value(Name, fun(V, Acc) -> [{Name, Type, V}|Acc] end, Metrics).

ioize(Atom) when is_atom(Atom) ->
    atom_to_binary(Atom, utf8);
ioize(Number) when is_float(Number) ->
    float_to_binary(Number, [{decimals, 4}]);
ioize(Number) when is_integer(Number) ->
    integer_to_binary(Number);
ioize(String) when is_list(String) ->
    list_to_binary(String);
ioize(Binary) when is_binary(Binary) ->
    Binary;
ioize({_,_,_,_} = IP) ->
    list_to_binary(inet:ntoa(IP));
ioize({_,_,_,_,_,_,_,_} = IP) ->
    list_to_binary(inet:ntoa(IP));
ioize(Something) ->
    iolist_to_binary(io_lib:format("~p", [Something])).

map_type(undefined)     -> <<"untyped">>;
map_type(counter)       -> <<"counter">>;
map_type(gauge)         -> <<"gauge">>;
map_type(spiral)        -> <<"gauge">>;
map_type(histogram)     -> <<"summary">>;
map_type(function)      -> <<"gauge">>;
map_type(Tuple) when is_tuple(Tuple) ->
    case element(1, Tuple) of
        function -> <<"gauge">>;
        _Else    -> <<"untyped">>
    end.

map_datapoint(value)    -> <<"">>;
map_datapoint(one)      -> <<"">>;
map_datapoint(n)        -> <<"_count">>;
map_datapoint(50)       -> <<"{quantile=\"0.5\"}">>;
map_datapoint(90)       -> <<"{quantile=\"0.9\"}">>;
map_datapoint(Integer) when is_integer(Integer)  ->
    Bin = integer_to_binary(Integer),
    <<"{quantile=\"0.", Bin/binary, "\"}">>;
map_datapoint(Something)  ->
    %% this is for functions with alternative datapoints
    Bin = ioize(Something),
    <<"{datapoint=\"", Bin/binary, "\"}">>.

is_valid_datapoint(count) -> false;
is_valid_datapoint(mean) -> false;
is_valid_datapoint(min) -> false;
is_valid_datapoint(max) -> false;
is_valid_datapoint(median) -> false;
is_valid_datapoint(ms_since_reset) -> false;
is_valid_datapoint(_Else) -> true.

maybe_add_sum(Name, DataPoints, histogram, Payload) ->
    Mean = proplists:get_value(mean, DataPoints),
    N = proplists:get_value(n, DataPoints),
    [Payload | [Name, <<"_sum ">>, ioize(Mean * N), <<"\n">>]];
maybe_add_sum(_Name, _DataPoints, _Type, Payload) ->
    Payload.

make_metric_name(Path) ->
    NameList = lists:join($_, lists:map(fun ioize/1, Path)),
    NameBin = iolist_to_binary(NameList),
    re:replace(NameBin, "-|\\.", "_", [global, {return,binary}]).

dp_error_response(Req) ->
    Node = capwap_dp:get_node(),
    Body = jsx:encode(#{
        type => <<"error">>,
        message => <<"Something is wrong with 'capwap-dp'">>,
        dp_node => list_to_binary(atom_to_list(Node)),
        ping_status => list_to_binary(atom_to_list(net_adm:ping(Node)))
    }),
    cowboy_req:reply(500, #{}, Body, Req).
