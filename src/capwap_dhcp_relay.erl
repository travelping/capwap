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
-define(DHCP_PORT, 67).

-record(s, {
    socket,
    servers,
    external_ip
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
    Cfg = application:get_env(capwap, dhcp_relay, []),
    ExternalIP = proplists:get_value(external_ip, Cfg, {0,0,0,0}),

    Servers = proplists:get_value(servers, Cfg, []),

    Options = [binary, inet, {reuseaddr, true}, {ip, ExternalIP} ],
    {ok, Socket} = gen_udp:open(?DHCP_PORT, Options),
    {ok, #s{socket = Socket,
            servers = queue:from_list(Servers),
            external_ip = ExternalIP}}.

handle_call(_Request, _From, State) ->
    lager:warning("capwap_dhcp_relay: Unhandled handle_call"),
    {reply, ok, State}.

handle_cast({send_to_dhcp, Packet},
            State = #s{socket = Socket, servers = Servers, external_ip = IP}) ->
    Decoded = dhcp_lib:decode(Packet),
    lager:debug("Get request from DP and send it to DHCP server ~p", [Decoded]),
    Decoded1 = Decoded#dhcp{
        giaddr = IP,
        hops = Decoded#dhcp.hops + 1
    },
    OutPacket = dhcp_lib:encode(Decoded1),
    {{value, Server}, NewServers} = queue:out(Servers),
    ok = gen_udp:send(Socket, Server, ?DHCP_PORT, OutPacket),
    {noreply, State#s{servers = queue:in(Server, NewServers)}};

handle_cast(_Request, State) ->
    lager:warning("capwap_dhcp_relay: Unhandled handle_cast"),
    {noreply, State}.

handle_info({udp, _Socket, _Ip, _Port, Packet}, State) ->
    Decoded = dhcp_lib:decode(Packet),
    lager:debug("Get reply from DHCP server and send it to DP ~p", [Decoded]),
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
