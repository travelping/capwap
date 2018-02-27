%% Copyright (C) 2018, Travelping GmbH <info@travelping.com>

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

-module(capwap_tools).

-export([format_eui/1, format_mac/1, format_ip/1, format_peer/1]).
-export([hexdump/1]).
-export([ip_csum/1]).
-export([may_learn/1, may_learn/2, eth_addr_is_reserved/1]).


format_eui(<<A:8, B:8, C:8, D:8, E:8, F:8>>) ->
    flat_format("~2.16.0B-~2.16.0B-~2.16.0B-~2.16.0B-~2.16.0B-~2.16.0B", [A, B, C, D, E, F]);
format_eui(MAC) ->
    flat_format("~w", MAC).

format_mac(<<A:8, B:8, C:8, D:8, E:8, F:8>>) ->
    flat_format("~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b", [A, B, C, D, E, F]);
format_mac(MAC) ->
    flat_format("~w", MAC).

format_ip(undefined) ->
    "undefined";
format_ip(<<A:8, B:8, C:8, D:8>>) ->
    flat_format("~B.~B.~B.~B", [A, B, C, D]);
format_ip(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    flat_format("~.16B:~.16B:~.16B:~.16B:~.16B:~.16B:~.16B:~.16B", [A, B, C, D, E, F, G, H]);
format_ip(IP) ->
    flat_format("~w", IP).

format_peer({IP, Port}) ->
    io_lib:format("~s:~w", [inet_parse:ntoa(IP), Port]);
format_peer(IP) ->
    io_lib:format("~p", [IP]).


flat_format(Format, Data) ->
    lists:flatten(io_lib:format(Format, Data)).


ip_csum(<<>>, CSum) ->
    CSum;
ip_csum(<<Head:8/integer>>, CSum) ->
    CSum + Head * 256;
ip_csum(<<Head:16/integer, Tail/binary>>, CSum) ->
    ip_csum(Tail, CSum + Head).

ip_csum(Bin) ->
    CSum0 = ip_csum(Bin, 0),
    CSum1 = ((CSum0 band 16#ffff) + (CSum0 bsr 16)),
    ((CSum1 band 16#ffff) + (CSum1 bsr 16)) bxor 16#ffff.


hexdump(Line, Part) ->
       L0 = [io_lib:format(" ~2.16.0B", [X]) || <<X:8>> <= Part],
       io_lib:format("~4.16.0B:~s~n", [Line * 16, L0]).

hexdump(_, <<>>, Out) ->
       lists:flatten(lists:reverse(Out));
hexdump(Line, <<Part:16/bytes, Rest/binary>>, Out) ->
       L1 = hexdump(Line, Part),
       hexdump(Line + 1, Rest, [L1|Out]);
hexdump(Line, <<Part/binary>>, Out) ->
       L1 = hexdump(Line, Part),
       hexdump(Line + 1, <<>>, [L1|Out]).

hexdump(List) when is_list(List) ->
       hexdump(0, list_to_binary(List), []);
hexdump(Bin) when is_binary(Bin)->
       hexdump(0, Bin, []).




may_learn(<<_:7, BCast:1, _/binary>> = _MAC) ->
    (BCast =/= 1).

may_learn(<<_:7, BCast:1, _/binary>> = _MAC, _VLan) ->
    (BCast =/= 1).

%%
%% Some well known Ethernet multicast addresses[11]
%% Ethernet multicast addressType FieldUsage
%% 01-00-0C-CC-CC-CC  0x0802      CDP (Cisco Discovery Protocol),
%%                                VTP (VLAN Trunking Protocol)
%% 01-00-0C-CC-CC-CD  0x0802      Cisco Shared Spanning Tree Protocol Address
%% 01-80-C2-00-00-00  0x0802      Spanning Tree Protocol (for bridges) IEEE 802.1D
%% 01-80-C2-00-00-08  0x0802      Spanning Tree Protocol (for provider bridges) IEEE 802.1AD
%% 01-80-C2-00-00-02  0x8809      Ethernet OAM Protocol IEEE 802.3ah (A.K.A. "slow protocols")
%% 01-00-5E-xx-xx-xx  0x0800      IPv4 Multicast (RFC 1112)
%% 33-33-xx-xx-xx-xx  0x86DD      IPv6 Multicast (RFC 2464)
%%
%% Returns true if it is a reserved multicast address, that a bridge must
%% never forward, false otherwise.
%%
eth_addr_is_reserved(<<16#01, 16#80, 16#C2, 16#00, 16#00, 0:4, _:4>>) ->
    true;
eth_addr_is_reserved(_Addr) ->
    false.

