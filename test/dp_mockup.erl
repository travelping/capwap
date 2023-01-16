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

-module(dp_mockup).

-compile({parse_transform, cut}).

%% API
-export([new/0, unload/0, clear/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API
%%%===================================================================

new() ->
    ok = meck:new(capwap_dp, [non_strict, no_link]),
    ok = meck:expect(capwap_dp, start_link, fun start_link/0),
    ok = meck:expect(capwap_dp, bind, fun bind/1),
    ok = meck:expect(capwap_dp, clear, fun clear/0),
    ok = meck:expect(capwap_dp, add_wtp, fun add_wtp/2),
    ok = meck:expect(capwap_dp, del_wtp, fun del_wtp/1),
    ok = meck:expect(capwap_dp, get_wtp, fun get_wtp/1),
    ok = meck:expect(capwap_dp, list_wtp, fun list_wtp/0),
    ok = meck:expect(capwap_dp, add_wlan, fun add_wlan/5),
    ok = meck:expect(capwap_dp, del_wlan, fun del_wlan/3),
    ok = meck:expect(capwap_dp, attach_station, fun attach_station/5),
    ok = meck:expect(capwap_dp, detach_station, fun detach_station/1),
    ok = meck:expect(capwap_dp, get_station, fun get_station/1),
    ok = meck:expect(capwap_dp, list_stations, fun list_stations/0),
    ok = meck:expect(capwap_dp, sendto, fun sendto/2),
    ok = meck:expect(capwap_dp, packet_out, fun packet_out/3),
    ok = meck:expect(capwap_dp, get_stats, fun get_stats/0),
    ok.

unload() ->
    ok = meck:unload(capwap_dp).

%%%===================================================================
%%% Internal functions
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

bind(Owner) ->
    gen_server:call(?SERVER, {bind, Owner}).

clear() ->
    gen_server:call(?SERVER, {clear}).

add_wtp(WTP, MTU) ->
    gen_server:call(?SERVER, {add_wtp, WTP, MTU}).

del_wtp(WTP) ->
    gen_server:call(?SERVER, {del_wtp, WTP}).

get_wtp(WTP) ->
    gen_server:call(?SERVER, {get_wtp, WTP}).

list_wtp() ->
    gen_server:call(?SERVER, {list_wtp}).

add_wlan(WTP, RadioId, WlanId, BSS, VlanId) ->
    gen_server:call(?SERVER, {add_wlan, WTP, RadioId, WlanId, BSS, VlanId}).

del_wlan(WTP, RadioId, WlanId) ->
    gen_server:call(?SERVER, {del_wlan, WTP, RadioId, WlanId}).

attach_station(WTP, STA, VlanId, RadioId, BSS) ->
    gen_server:call(?SERVER, {attach_station, WTP, STA, VlanId, RadioId, BSS}).

detach_station(STA) ->
    gen_server:call(?SERVER, {detach_station, STA}).

get_station(STA) ->
    gen_server:call(?SERVER, {get_station, STA}).

list_stations() ->
    gen_server:call(?SERVER, {list_stations}).

sendto(WTP, Msg) when is_binary(Msg) ->
    gen_server:call(?SERVER, {sendto, WTP, Msg}).

packet_out(tap, VlanId, Msg) when is_binary(Msg) ->
    gen_server:call(?SERVER, {packet_out, tap, VlanId, Msg}).

get_stats() ->
    gen_server:call(?SERVER, {get_stats}).

%%===================================================================
%% gen_server callbacks
%%===================================================================

-record(wtp, {wlans = #{}, stations = #{}}).

init([]) ->
    {ok, #{}}.

handle_call({add_wlan, WTP, RadioId, WlanId, BSS, VlanId}, _From, State) ->
    Id = {RadioId, WlanId},
    WLAN = {BSS, VlanId},
    {reply, ok, wtp_add_wlan(WTP, Id, WLAN, State)};

handle_call({del_wlan, WTP, RadioId, WlanId}, _From, State)
  when is_map_key(WTP, State) ->
    Id = {RadioId, WlanId},
    {reply, ok, maps:update_with(WTP, wtp_del_wlan(Id, _), State)};

handle_call({attach_station, WTP, STA, VlanId, RadioId, BSS}, _From, State)
  when is_map_key(WTP, State) ->
    Station = {VlanId, RadioId, BSS},
    {reply, ok, maps:update_with(WTP, wtp_attach_station(STA, Station, _), State)};

handle_call({get_wtp, WTP}, _From, State) ->
    #wtp{wlans = Wlans, stations = Stations} = maps:get(WTP, State, #wtp{}),
    Ws = maps:fold(
	   fun({RadioId, WlanId}, {BSS, VlanId}, L) ->
		   [{RadioId, WlanId, BSS, VlanId}|L] end, [], Wlans),
    STAs = maps:fold(
	     fun(STA, {VlanId, RadioId, BSS}, L) ->
		     [{STA, VlanId, RadioId, BSS, {0,0,0,0}}|L] end, [], Stations),
    WTPCnts = {0, 0, 0, 0, 0, 0, 0, 0, 0},
    Reply = {WTP, Ws, STAs, 1, 1500, WTPCnts},
    {reply, Reply, State};

handle_call({get_station, STA}, _From, State) ->
    %% only fill values required for test case
    Stats = {STA, 'VLan', 'RadioId', 'BSS',
	     {_RcvdPkts = 1, _SendPkts = 2, _RcvdBytes = 3, _SendBytes = 4}},
    {reply, Stats, State};

handle_call({clear}, _From, _State) ->
    {reply, ok, #{}};

handle_call(_Request, _From, State) ->
    ct:pal("Call: ~p", [_Request]),
    {reply, ok, State}.

handle_cast(_Request, State) ->
    ct:pal("Cast: ~p", [_Request]),
    {noreply, State}.

handle_info(_Info, State) ->
    ct:pal("Info: ~p", [_Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%===================================================================
%% Internal functions
%%===================================================================

wtp_add_wlan(WTP, Id, WLAN, State) ->
    maps:update_with(WTP, wtp_add_wlan(Id, WLAN, _), #wtp{wlans = #{Id => WLAN}}, State).

wtp_add_wlan(Id, WLAN, #wtp{wlans = Wlans} = WTP) ->
    WTP#wtp{wlans = maps:put(Id, WLAN, Wlans)}.

wtp_del_wlan(Id, #wtp{wlans = Wlans} = WTP) ->
    WTP#wtp{wlans = maps:remove(Id, Wlans)}.

wtp_attach_station(STA, Station, #wtp{stations = STAs} = WTP) ->
    WTP#wtp{stations = maps:put(STA, Station, STAs)}.
