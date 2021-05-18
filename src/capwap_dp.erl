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

-module(capwap_dp).

-behavior(gen_server).

%% API
-export([start_link/0]).

%% C-Node wrapper
-export([bind/1, clear/0, get_stats/0]).
-export([add_wtp/2, del_wtp/1, get_wtp/1, list_wtp/0]).
-export([add_wlan/5, del_wlan/3]).
-export([attach_station/5, detach_station/1, get_station/1, list_stations/0]).
-export([sendto/2, packet_out/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% dev API
-export([run/1, get_node/0]).

-include_lib("kernel/include/logger.hrl").
-include("include/capwap_packet.hrl").

-record(state, {state, tref, timeout, interim, interim_timer, api_version}).

-define(SERVER, ?MODULE).

%%===================================================================
%% API
%%===================================================================
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%===================================================================
%% C-Node API Wrapper
%%===================================================================

bind(Owner) ->
    call({bind, Owner}).

clear() ->
    call({clear}).

add_wtp(WTP, MTU) ->
    call({add_wtp, WTP, MTU}).

del_wtp(WTP) ->
    call({del_wtp, WTP}).

get_wtp(WTP) ->
    call({get_wtp, WTP}).

list_wtp() ->
    call({list_wtp}).

add_wlan(WTP, RadioId, WlanId, BSS, VlanId) ->
    call({add_wlan, WTP, RadioId, WlanId, BSS, VlanId}).

del_wlan(WTP, RadioId, WlanId) ->
    call({del_wlan, WTP, RadioId, WlanId}).

attach_station(WTP, STA, VlanId, RadioId, BSS) ->
    call({attach_station, WTP, STA, VlanId, RadioId, BSS}).

detach_station(STA) ->
    call({detach_station, STA}).

get_station(STA) ->
    call({get_station, STA}).

list_stations() ->
    call({list_stations}).

sendto(WTP, Msg) when is_binary(Msg) ->
    call({sendto, WTP, Msg}).

packet_out(tap, VlanId, Msg) when is_binary(Msg) ->
    call({packet_out, tap, VlanId, Msg}).

get_stats() ->
    call({get_stats}).

call(Args) ->
    call(Args, infinity).

call(Args, Timeout) ->
    Node = get_node(),
    gen_server:call({capwap, Node}, Args, Timeout).

%%===================================================================
%% gen_server callbacks
%%===================================================================
init([]) ->
    State = connect(#state{state = disconnected, tref = undefined, timeout = 10, interim = 30 * 1000}),
    {ok, State}.

handle_call(Request, _From, State = #state{state = disconnected}) ->
    ?LOG(warning, "got call ~p without active data path", [Request]),
    {reply, {error, not_connected}, State};

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(Request, State = #state{state = disconnected}) ->
    ?LOG(warning, "got cast ~p without active data path", [Request]),
    {noreply, State};

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({nodedown, Node}, State0) ->
    ?LOG(warning, "node down: ~p", [Node]),

    State1 = handle_nodedown(State0),
    State2 = start_nodedown_timeout(State1),
    {noreply, State2};

handle_info(reconnect, State0) ->
    ?LOG(warning, "trying to reconnect"),
    State1 = connect(State0#state{tref = undefined}),
    {noreply, State1};

handle_info(Info, State = #state{state = disconnected}) ->
    ?LOG(warning, "got info ~p without active data path", [Info]),
    {noreply, State};

handle_info({packet_in, tap, VlanId, Packet}, State) ->
    ?LOG(debug, "TAP: ~p", [Packet]),
    <<MAC:6/bytes, _/binary>> = Packet,
    case MAC of
	<<255, 255, 255, 255, 255, 255>> ->
	    ?LOG(warning, "need to handle broadcast on VLAN ~w", [VlanId]),
	    ok;

	<<_:7, 1:1, _/binary>> ->
	    ?LOG(warning, "need to handle multicast on VLAN ~w to ~s", [VlanId, capwap_tools:format_eui(MAC)]),
	    ok;

	_ ->
	    ?LOG(warning, "packet for invalid STA ~s on VLAN ~w", [capwap_tools:format_eui(MAC), VlanId]),
	    ok
    end,
    {noreply, State};

handle_info({capwap_in, WTPDataChannelAddress, Msg}, State) ->
    ?LOG(warning, "CAPWAP from ~p: ~p", [WTPDataChannelAddress, Msg]),
    erlang:spawn(capwap_ac, handle_data, [self(), WTPDataChannelAddress, Msg]),
    {noreply, State};

handle_info({wtp_down, WTP}, State) ->
    ?LOG(warning, "WTP DOWN: ~p", [WTP]),
    del_wtp(WTP),
    {noreply, State};

handle_info({timeout, TRef, interim},
	    #state{interim_timer = TRef} = State0) ->
    report_stats(),
    State = start_interim(State0),
    {noreply, State};

handle_info(Info, State) ->
    ?LOG(warning, "Unhandled info message: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

get_node() ->
    DP = application:get_env(capwap, 'capwap-dp', "capwap-dp"),
    list_to_atom(DP ++ "@" ++ net_adm:localhost()).

start_nodedown_timeout(State = #state{tref = undefined, timeout = Timeout}) ->
    NewTimeout = if Timeout < 3000 -> Timeout * 2;
		    true           -> Timeout
		 end,
    TRef = erlang:send_after(Timeout, self(), reconnect),
    State#state{tref = TRef, timeout = NewTimeout};

start_nodedown_timeout(State) ->
    State.

start_interim(#state{interim = Interim} = State) ->
    TRef = erlang:start_timer(Interim, self(), interim),
    State#state{interim_timer = TRef}.

stop_interim(#state{interim_timer = TRef} = State) ->
    cancel_timer(TRef),
    State#state{interim_timer = undefined}.

connect(State0) ->
    Node = get_node(),
    case net_adm:ping(Node) of
	pong ->
	    ?LOG(warning, "Node ~p is up", [Node]),
	    erlang:monitor_node(Node, true),
	    clear(),
	    {ok, APIVersion} = bind(self()),
	    report_stats(),
	    State1 = start_interim(State0),
	    State1#state{state = connected, timeout = 10, api_version = APIVersion};
	pang ->
	    ?LOG(warning, "Node ~p is down", [Node]),
	    start_nodedown_timeout(State0)
    end.

handle_nodedown(State0) ->
    State1 = stop_interim(State0),
    State1#state{state = disconnected}.

%% Returns the remaing time for the timer if Ref referred to
%% an active timer/send_event_after, false otherwise.
cancel_timer(Ref) when is_reference(Ref) ->
    case erlang:cancel_timer(Ref) of
        false ->
            receive {timeout, Ref, _} -> 0
            after 0 -> false
            end;
        RemainingTime ->
            RemainingTime
    end;
cancel_timer(_) ->
    false.

wtp_stats_sum({RcvdPkts0, SendPkts0, RcvdBytes0, SendBytes0,
	       RcvdFragments0, SendFragments0,
	       ErrInvalidStation0, ErrFragmentInvalid0, ErrFragmentTooOld0,
	       ErrInvalidWtp0, ErrHdrLengthInvalid0,
	       ErrTooShort0, RatelimitUnknownWtp0},
	      {RcvdPkts1, SendPkts1, RcvdBytes1, SendBytes1,
	       RcvdFragments1, SendFragments1,
	       ErrInvalidStation1, ErrFragmentInvalid1, ErrFragmentTooOld1,
	       ErrInvalidWtp1, ErrHdrLengthInvalid1,
	       ErrTooShort1, RatelimitUnknownWtp1}) ->
    {RcvdPkts0 + RcvdPkts1, SendPkts0 + SendPkts1,
     RcvdBytes0 + RcvdBytes1, SendBytes0 + SendBytes1,
     RcvdFragments0 + RcvdFragments1, SendFragments0 + SendFragments1,
     ErrInvalidStation0 + ErrInvalidStation1,
     ErrFragmentInvalid0 + ErrFragmentInvalid1,
     ErrFragmentTooOld0 + ErrFragmentTooOld1,
     ErrInvalidWtp0 + ErrInvalidWtp1,
     ErrHdrLengthInvalid0 + ErrHdrLengthInvalid1,
     ErrTooShort0 + ErrTooShort1,
     RatelimitUnknownWtp0 + RatelimitUnknownWtp1}.

wtp_stats_to_accouting({RcvdPkts, SendPkts, RcvdBytes, SendBytes,
			RcvdFragments, SendFragments,
			ErrInvalidStation, ErrFragmentInvalid, ErrFragmentTooOld,
			ErrInvalidWtp, ErrHdrLengthInvalid,
			ErrTooShort, RatelimitUnknownWtp}) ->
    [{'InPackets',  RcvdPkts},
     {'OutPackets', SendPkts},
     {'InOctets',   RcvdBytes},
     {'OutOctets',  SendBytes},
     {'Received-Fragments',     RcvdFragments},
     {'Send-Fragments',         SendFragments},
     {'Error-Invalid-Stations', ErrInvalidStation},
     {'Error-Fragment-Invalid', ErrFragmentInvalid},
     {'Error-Fragment-Too-Old', ErrFragmentTooOld},
     {'Error-Invalid-WTP',      ErrInvalidWtp},
     {'Error-Header-Length-Invalid', ErrHdrLengthInvalid},
     {'Error-Too-Short',        ErrTooShort},
     {'Rate-Limit-Unknown-WTP', RatelimitUnknownWtp}];
wtp_stats_to_accouting(_) ->
    [].

exo_report_stats(Thread, ProcessStats) ->
    Acc = wtp_stats_to_accouting(ProcessStats),
    lists:foreach(fun ({Key, Value}) ->
			  prometheus_counter:inc(metric(Key), [Thread], Value)
		  end, Acc).

metric('InPackets') -> capwap_dp_in_packets_total;
metric('OutPackets') -> capwap_dp_out_packets_total;
metric('InOctets') -> capwap_dp_in_octets_total;
metric('OutOctets') -> capwap_dp_out_octets_total;
metric('Received-Fragments') -> capwap_dp_received_fragments_total;
metric('Send-Fragments') -> capwap_dp_send_fragments_total;
metric('Error-Invalid-Stations') -> capwap_dp_error_invalid_stations_total;
metric('Error-Fragment-Invalid') -> capwap_dp_error_fragment_invalid_total;
metric('Error-Fragment-Too-Old') -> capwap_dp_error_fragment_too_old_total;
metric('Error-Invalid-WTP') -> capwap_dp_error_invalid_wtp;
metric('Error-Header-Length-Invalid') -> capwap_dp_error_header_length_invalid;
metric('Error-Too-Short') -> capwap_dp_error_too_short;
metric('Rate-Limit-Unknown-WTP') -> capwap_dp_rate_limit_unknown_wtp.

report_stats(ProcessStats, {Cnt, Sum}) ->
    exo_report_stats(integer_to_list(Cnt), ProcessStats),
    {Cnt + 1, wtp_stats_sum(ProcessStats, Sum)}.

report_stats() ->
    case call({get_stats}, 100) of
	Stats when is_list(Stats) ->
	    SumInit = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	    {_Cnt, Sum} = lists:foldl(fun report_stats/2, {0, SumInit}, Stats),
	    exo_report_stats("all", Sum),
	    ok;
	Other ->
	    ?LOG(warning, "WTP Stats: ~p", [Other]),
	    ok
    end.

%%%===================================================================
%%% Development helper
%%%===================================================================

run(WTP) ->
    bind(self()),
    add_wtp(WTP, 1400),
    run_loop(WTP).

run_loop(WTP) ->
    receive
	{packet_in, tap, Packet} ->
	    io:format("Packet-In: ~p~n", [Packet]),
	    <<MAC:6/bytes, _/binary>> = Packet,
        case {capwap_tools:eth_addr_is_reserved(MAC), capwap_tools:may_learn(MAC)} of
		{false, true} ->
		    io:format("install STA: ~p~n", [MAC]),
		    RadioId = 1,
		    BSS = <<1,1,1,1,1,1>>,
		    attach_station(WTP, MAC, 0, RadioId, BSS);

		_ ->
		    ok
	    end,
	    Data = capwap_packet:encode(data, {#capwap_header{radio_id = 1, wb_id = 2, flags = [{frame, '802.3'}]}, Packet}),
	    [sendto(WTP, X) || X <- Data],
	    ok;

	{capwap_in, WTPDataChannelAddress, Msg} ->
	    io:format("CAPWAP From ~p: ~p~n", [WTPDataChannelAddress, Msg]),
	    ok;

	Other ->
	    io:format("Other: ~p~n", [Other]),
	    ok
    end,
    run_loop(WTP).
