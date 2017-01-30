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

-module(capwap_packet_SUITE).

-compile(export_all).

%-include("../include/capwap_packet.hrl").
-include_lib("common_test/include/ct.hrl").

-define(equal(Expected, Actual),
    (fun (Expected@@@, Expected@@@) -> true;
         (Expected@@@, Actual@@@) ->
             ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
                    [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
             false
     end)(Expected, Actual) orelse error(badmatch)).

capwap_discovery_request() ->
    hexstr2bin("002002100000000006f81a674d70b30000000001090061000014000101002600"
	       "1400005ba0000000040001e240000100040001e2400027002a010101010a0900"
	       "005ba0000000040001e24000005ba0000100040000303b00005ba00002000400"
	       "12d6880029000108002c000101041800050000000005").

capwap_discovery_response() ->
    hexstr2bin("0010020000000000000000020900480000010024000000c80000000f00000002"
	       "0000ff98000400040012dac80000ff98000500040031b29800040006204d7920"
	       "4143000a0006c0a80d550000041800050000000000").

capwap_join_request() ->
    hexstr2bin("002002100000000006f81a674d70b300000000030a009800001c001020204e65"
	       "787420746f204672696467650026001400005ba0000000040001e24000010004"
	       "0001e2400027002a010101010a0900005ba0000000040001e24000005ba00001"
	       "00040000303b00005ba0000200040012d688001e0004c0a80101002d00084d79"
	       "20575450203100230010f81a674d70b3f81a674d70b34bdd8344002900010800"
	       "2c000101041800050000000005").

capwap_join_response() ->
    hexstr2bin("0010020000000000000000040a00500000010024000000c80001000f00000002"
	       "0000ff98000400040012dac80000ff98000500040031b29800040006204d7920"
	       "4143000a0006c0a80d5500010418000500000000000021000400000000").

capwap_configuration_status_request() ->
    hexstr2bin("002002100000000006f81a674d70b300000000050b006c0000040006204d7920"
	       "41430005000a0041435072696d6172790005000c0141435365636f6e64617279"
	       "001f000200010024000200780030000f00000000000000000000000000000004"
	       "1800050000000005041000090082848b960c1218240408000800000001000e00"
	       "1b").

capwap_configuration_status_response() ->
    hexstr2bin("0010020000000000000000060b007300000200080201a8c04201a8c000030020"
	       "5f1bdf00ce3ee200002008002078e3e35f1bdf00ce3ee200002008002078e3e4"
	       "000c000214020010000300000f001700040000000a0028000100041500220000"
	       "00000200030100000000030004010000000003000a020000000004000a070000").

capwap_change_state_request() ->
    hexstr2bin("002002100000000006f81a674d70b3000000000b0c0012000020000300010000"
	       "21000400000000").

capwap_change_state_response() ->
    hexstr2bin("00100200000000000000000c0c000300").

capwap_wlan_configuration_request() ->
    hexstr2bin("00100200000000000033dd0100001e0004000017000080200000000000000000"
	       "0000000001020174657374").

capwap_wlan_configuration_response() ->
    hexstr2bin("002002100000000006f81a674d70b3000033dd02000017000021000400000000"
	       "0025000800005ba000000000").

capwap_station_configuration_request() ->
    hexstr2bin("0010020000000000000000191d000f000008000800069027e440b913").

capwap_station_configuration_response() ->
    hexstr2bin("002002100000000006f81a674d70b3000000001a1d000b000021000400000000").

capwap_echo_request() ->
    hexstr2bin("002002100000000006f81a674d70b3000000000d05000300").

capwap_echo_response() ->
    hexstr2bin("00100200000000000000000e05000300").

capwap_wwan_stats_long() ->
    Frag1 = hexstr2bin("00104280000000000000000905098E000025000A000048F9000256A506540025"
		       "001A000048F900015406984D01011901484DFFFF418010000000760500250031"
		       "000048F9000F5406984D01244750534143503A203030303030302E3030302C2C"
		       "2C2C2C302C2C2C2C3030303030302C30300025001A000048F90001540698C401"
		       "011901484DFFFF418010000000760500250031000048F9000F540698C4012447"
		       "50534143503A203030303030302E3030302C2C2C2C2C302C2C2C2C3030303030"
		       "302C30300025001A000048F900015406993C01011901484DFFFF418010000000"
		       "760500250031000048F9000F5406993C01244750534143503A20303030303030"
		       "2E3030302C2C2C2C2C302C2C2C2C30303030303030302E3030302C2C2C2C2C30"
		       "2C2C2C2C3030303030302C30300025001A000048F9000154069AA40101190148"
		       "4DFFFF418010000000760500250031000048F9000F54069AA401244750534143"
		       "503A203030303030302E3030302C2C2C2C2C302C2C2C2C3030303030302C3030"
		       "0025001A000048F9000154069B1C01011901484DFFFF41801000000076050025"
		       "0031000048F9000F54069B1C01244750534143503A203030303030302E303030"
		       "2C2C2C2C2C302C2C2C2C3030303030302C30300025001A000048F9000154069B"
		       "9401011901484DFFFF418010000000760500250031000048F9000F54069B9401"
		       "244750534143503A203030303030302E3030302C2C2C2C2C302C2C2C2C303030"
		       "3030302C30300025001A000048F9000154069C0C01011901484DFFFF41801000"
		       "0000760500250031000048F9000F54069C0C01244750534143503A2030303030"
		       "30302E3030302C2C2C2C2C302C2C2C2C3030303030302C30300025001A000048"
		       "F9000154069C8401011901484DFFFF418010000000760500250031000048F900"
		       "0F54069C8401244750534143503A203030303030302E3030302C2C2C2C2C302C"
		       "2C2C2C3030303030302C30300025001A000048F9000154069CFC01011901484D"
		       "FFFF418010000000760500250031000048F9000F54069CFC0124475053414350"
		       "3A203030303030302E3030302C2C2C2C2C302C2C2C2C3030303030302C303000"
		       "25001A000048F9000154069D7401011901484DFFFF4180100000007605002500"
		       "31000048F9000F54069D7401244750534143503A203030303030302E3030302C"
		       "2C2C2C2C302C2C2C2C3030303030302C30300025001A000048F9000154069DEC"
		       "01011901484DFFFF418010000000760500250031000048F9000F54069DEC0124"
		       "4750534143503A203030303030302E3030302C2C2C2C2C302C2C2C2C30303030"
		       "30302C30300025001A000048F9000154069E6401011901484DFFFF4180100000"
		       "00760500250031000048F9000F54069E6401244750534143503A203030303030"
		       "302E3030302C2C2C2C2C302C2C2C2C3030303030302C30300025001A000048F9"
		       "000154069EDC01011901484D0000418010000000760500250031000048F9000F"
		       "54069EDC01244750534143503A203030303030302E3030302C2C2C2C2C302C2C"
		       "2C2C3030303030302C30300025001A000048F9000154069F5401011901484D00"
		       "00418010000000760500250031000048F9000F54069F5401244750534143503A"
		       "203030303030302E3030302C2C2C2C2C302C2C2C2C3030303030302C30300025"),
    Frag2 = hexstr2bin("001042C000002A40001A000048F9000154069FCC01011901484DFFFF41801000"
		       "000048F900015406A0BC01011901484D00004180100000007605002500310000"
		       "48F9000F5406A0BC01244750534143503A203030303030302E3030302C2C2C2C"
		       "2C302C2C2C2C3030303030302C30300025001A000048F900015406A134010119"
		       "01484D0000418010000000760500250031000048F9000F5406A1340124475053"
		       "4143503A203030303030302E3030302C2C2C2C2C302C2C2C2C3030303030302C"
		       "30300025001A000048F900015406A1AC01011901484D00004180100000007605"
		       "00250031000048F9000F5406A1AC01244750534143503A203030303030302E30"
		       "30302C2C2C2C2C302C2C2C2C3030303030302C30300025001A000048F9000154"
		       "06A22401011901484DFFFF418010000000760500250031000048F9000F5406A2"
		       "2401244750534143503A203030303030302E3030302C2C2C2C2C302C2C2C2C30"
		       "30303030302C30300025001A000048F900015406A29C01011901484DFFFF4180"
		       "10000000760500250031000048F9000F5406A29C01244750534143503A203030"
		       "303030302E3030302C2C2C2C2C302C2C2C2C3030303030302C30300025001A00"
		       "0048F900015406A31401011901484DFFFF418010000000760500250031000048"
		       "F9000F5406A31401244750534143503A203030303030302E3030302C2C2C2C2C"
		       "302C2C2C2C3030303030302C30300025001A000048F900015406A38C01011901"
		       "484DFFFF418010000000760500250031000048F9000F5406A38C012447505341"
		       "43503A203030303030302E3030302C2C2C2C2C302C2C2C2C3030303030302C30"
		       "300025001A000048F900015406A40401011901484DFFFF418010000000760500"
		       "250031000048F9000F5406A40401244750534143503A203030303030302E3030"
		       "302C2C2C2C2C302C2C2C2C3030303030302C30300025001A000048F900015406"
		       "A47C01011901484DFFFF418010000000760500250031000048F9000F5406A47C"
		       "01244750534143503A203030303030302E3030302C2C2C2C2C302C2C2C2C3030"
		       "303030302C30300025001A000048F900015406A4F401011901484DFFFF418010"
		       "000000760500250031000048F9000F5406A4F401244750534143503A20303030"
		       "3030302E3030302C2C2C2C2C302C2C2C2C3030303030302C30300025001A0000"
		       "48F900015406A53B01011901484D0000418010000000760500250031000048F9"
		       "000F5406A53B01244750534143503A203030303030302E3030302C2C2C2C2C30"
		       "2C2C2C2C3030303030302C303000250012000048F9000B000000000000000000"
		       "000000"),
    [Frag1, Frag2].

% hexstr2bin
hexstr2bin(S) ->
    list_to_binary(hexstr2list(S)).

hexstr2list([X,Y|T]) ->
    [mkint(X)*16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
    [].

mkint(C) when $0 =< C, C =< $9 ->
    C - $0;
mkint(C) when $A =< C, C =< $F ->
    C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
    C - $a + 10.

%%--------------------------------------------------------------------
%% @spec suite() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
suite() ->
	[{timetrap,{seconds,30}}].

test_discovery_request(_Config) ->
    Msg = capwap_discovery_request(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_discovery_reponse(_Config) ->
    Msg = capwap_discovery_response(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_join_request(_Config) ->
    Msg = capwap_join_request(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_join_response(_Config) ->
    Msg = capwap_join_response(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_configuration_status_request(_Config) ->
    Msg = capwap_configuration_status_request(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_configuration_status_response(_Config) ->
    Msg = capwap_configuration_status_response(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_change_state_request(_Config) ->
    Msg = capwap_change_state_request(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_change_state_response(_Config) ->
    Msg = capwap_change_state_response(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_wlan_configuration_request(_Config) ->
    Msg = capwap_wlan_configuration_request(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_wlan_configuration_response(_Config) ->
    Msg = capwap_wlan_configuration_response(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_station_configuration_request(_Config) ->
    Msg = capwap_station_configuration_request(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_station_configuration_response(_Config) ->
    Msg = capwap_station_configuration_response(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_echo_request(_Config) ->
    Msg = capwap_echo_request(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.
test_echo_response(_Config) ->
    Msg = capwap_echo_response(),
    R = capwap_packet:decode(control, Msg),
    ct:pal("R: ~p~n", [R]),
    ?equal([Msg], capwap_packet:encode(control, R)),
    ok.

test_wwan_stats_long(_Config) ->
    Msgs = capwap_wwan_stats_long(),
    lists:foreach(fun(F) -> R = capwap_packet:decode(control, F),
			    ct:pal("R: ~p~n", [R]),
			    if element(1, R) == fragment -> ok;
			       true -> ct:fail("unexpected return: ~p", [R])
			    end
		  end, Msgs),
    ok.

all() ->
    [test_discovery_request,
     test_discovery_reponse,
     test_join_request,
     test_join_response,
     test_configuration_status_request,
     test_configuration_status_response,
     test_change_state_request,
     test_change_state_response,
     test_wlan_configuration_request,
     test_wlan_configuration_response,
     test_station_configuration_request,
     test_station_configuration_response,
     test_echo_request,
     test_echo_response,
     test_wwan_stats_long
    ].

init_per_suite(Config) ->
	Config.

end_per_suite(_Config) ->
	ok.

