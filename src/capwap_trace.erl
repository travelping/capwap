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

-module(capwap_trace).

-behaviour(gen_event).

%% API
-export([start_link/0, add_handler/1, trace/3, start_tracer/0]).

%% gen_event callbacks
-export([init/1, handle_event/2, handle_call/2,
         handle_info/2, terminate/2, code_change/3]).

-include_lib("kernel/include/logger.hrl").

-define(SERVER, ?MODULE).

-record(state, {file}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_event:start_link({local, ?SERVER}).

add_handler(File) ->
    gen_event:add_handler(?SERVER, ?MODULE, [File]).

start_tracer() ->
    ?LOG(debug, "TRACE: ~p", [application:get_env('trace-file')]),
    case application:get_env('trace-file') of
        {ok, File} ->
            R = capwap_sup:start_tracer(File),
            ?LOG(debug, "TRACE: ~p", [R]),
            ok;
        _ ->
            ok
    end.

trace(Src, Dest, Data) ->
    case whereis(?SERVER) of
        Pid when is_pid(Pid) ->
            gen_event:notify(?SERVER, {trace, Src, Dest, Data});
        _ ->
            ok
    end.

%%%===================================================================
%%% gen_event callbacks
%%%===================================================================

init([File]) ->
    ?LOG(debug, "Starting TRACE handler"),
    case filelib:ensure_dir(filename:dirname(File)) of
        ok ->
            case file:open(File, [write, raw]) of
                {ok, Io} ->
                    Header = << (pcapng_shb())/binary, (pcapng_ifd(<<"CAPWAP">>))/binary >>,
                    file:write(Io, Header),
                    {ok, #state{file = Io}};
                {error, _} = Other ->
                    ?LOG(error, "Starting TRACE handler failed with ~p", [Other]),
                    Other
            end;
        {error, _} = Other ->
            ?LOG(error, "Starting TRACE handler failed with ~p", [Other]),
            Other
    end.

handle_event({trace, {SrcIP = {_,_,_,_}, SrcPort}, {DstIP, DstPort}, Data},
             #state{file = Io} = State) ->
    Packet = make_udp(tuple_to_ip(SrcIP), tuple_to_ip(DstIP), SrcPort, DstPort, Data),
    Dump = format_pcapng(Packet),
    file:write(Io, Dump),
    {ok, State};
handle_event(_Event, State) ->
    ?LOG(error, "TRACE handler: ~p", [_Event]),
    {ok, State}.

handle_call(_Request, State) ->
    Reply = ok,
    {ok, Reply, State}.

handle_info(_Info, State) ->
    {ok, State}.

terminate(_Reason, #state{file = Io}) ->
    file:close(Io),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-define(PCAPNG_VERSION_MAJOR, 1).
-define(PCAPNG_VERSION_MINOR, 0).
-define(LINKTYPE_ETHERNET, 1).
-define(LINKTYPE_RAW, 101).

tuple_to_ip({A, B, C, D}) ->
    <<A:8, B:8, C:8, D:8>>;
tuple_to_ip({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

make_udp(NwSrc, NwDst, TpSrc, TpDst, PayLoad) ->
    Id = 0,
    Proto = 17,

    UDPLength = 8 + size(PayLoad),
    UDPCSum = capwap_tools:ip_csum(<<NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8,
                                     0:8, Proto:8, UDPLength:16,
                                     TpSrc:16, TpDst:16, UDPLength:16, 0:16,
                                     PayLoad/binary>>),
    UDP = <<TpSrc:16, TpDst:16, UDPLength:16, UDPCSum:16, PayLoad/binary>>,

    TotLen = 20 + size(UDP),
    HdrCSum = capwap_tools:ip_csum(<<4:4, 5:4, 0:8, TotLen:16,
                                     Id:16, 0:16, 64:8, Proto:8,
                                     0:16/integer, NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8>>),
    IP = <<4:4, 5:4, 0:8, TotLen:16,
           Id:16, 0:16, 64:8, Proto:8,
           HdrCSum:16/integer, NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8>>,
    list_to_binary([IP, UDP]).

format_pcapng(Msg) ->
    TStamp = os:system_time(micro_seconds),
    Len = size(Msg),
    pcapng:encode({epb, 0, TStamp, Len, [], Msg}).

pcapng_shb() ->
    pcapng:encode({shb, {?PCAPNG_VERSION_MAJOR, ?PCAPNG_VERSION_MINOR},
                   [{os, <<"CAROS">>}, {userappl, <<"CAPWAP">>}]}).

pcapng_ifd(Name) ->
    pcapng:encode({ifd, ?LINKTYPE_RAW, 65535,
                   [{name,    Name},
                    {tsresol, <<6>>},
                    {os,      <<"CAROS">>}]}).
