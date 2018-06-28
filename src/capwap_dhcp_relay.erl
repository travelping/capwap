%% Copyright (C) 2013-2018, Travelping GmbH <info@travelping.com>

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

-module(capwap_dhcp_relay).

-behavior(gen_server).

-include_lib("dhcp/include/dhcp.hrl").

%% API
-export([start_link/0]).
-export([send_to_dhcp/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(FROM_ADDRESS, {192,168,86,10}).
-define(DHCP_SERVER, {192,168,81,1}).
-define(DHCP_PORT, 67).

-record(s, {
    socket
}).

%%===================================================================
%% API
%%===================================================================
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

send_to_dhcp(Packet) ->
    gen_server:cast(?SERVER, {send_to_dhcp, Packet}).

%%===================================================================
%% gen_server callbacks
%%===================================================================
init([]) ->
    {ok, Socket} = gen_udp:open(?DHCP_PORT, [binary, inet, {reuseaddr, true}, {ip, ?FROM_ADDRESS}]),
    {ok, #s{socket = Socket}}.

handle_call(_Request, _From, State) ->
    lager:warning("capwap_dhcp_relay: Unhandled handle_call"),
    {reply, ok, State}.

handle_cast({send_to_dhcp, Packet}, State = #s{socket = Socket}) ->
    Decoded = dhcp_lib:decode(Packet),
    Decoded1 = Decoded#dhcp{
        giaddr = ?FROM_ADDRESS,
        hops = Decoded#dhcp.hops + 1
    },
    OutPacket = dhcp_lib:encode(Decoded1),

    ok = gen_udp:send(Socket, ?DHCP_SERVER, ?DHCP_PORT, OutPacket),
    {noreply, State};

handle_cast(_Request, State) ->
    lager:warning("capwap_dhcp_relay: Unhandled handle_cast"),
    {noreply, State}.

handle_info({udp, _Socket, _Ip, _Port, Packet}, State) ->
    Decoded = dhcp_lib:decode(Packet),
    Decoded1 = Decoded#dhcp{
        hops = Decoded#dhcp.hops + 1,
        giaddr = {0, 0, 0, 0}
    },

    OutPacket = dhcp_lib:encode(Decoded1),
    capwap_dp:send_dhcp_packet(OutPacket),
    {noreply, State};

handle_info(Info, State) ->
    lager:warning("Unhandled info message: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, #s{socket = Socket}) ->
    gen_udp:close(Socket),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
