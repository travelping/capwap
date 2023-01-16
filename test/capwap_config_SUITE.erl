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

-module(capwap_config_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include("capwap_config.hrl").

-define(equal(Expected, Actual),
    (fun (Expected@@@, Expected@@@) -> true;
	 (Expected@@@, Actual@@@) ->
	     ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
		    [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
	     false
     end)(Expected, Actual) orelse error(badmatch)).


-define(match(Guard, Expr),
	((fun () ->
		  case (Expr) of
		      Guard -> ok;
		      V -> ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~s~n",
				   [?FILE, ?LINE, ??Expr, ??Guard, pretty_print(V)]),
			    error(badmatch)
		  end
	  end)())).

suite() ->
	[{timetrap,{seconds,30}}].

all() ->
    [json_to_rec].

init_per_suite(Config) ->
	Config.

end_per_suite(_Config) ->
	ok.

%% ==============================================
%% Tests
%% ==============================================

do_json_to_rec(Config, DataFile) ->
    JSON = read_json(Config, DataFile),
    ct:pal("JSON: ~p", [JSON]),
    Cfg = maps:get(config, JSON),
    Res = capwap_config_http:transform_values(Cfg),
    ct:pal("Res: ~p", [Res]),
    Rec = capwap_config:'#frommap-wtp'(Res),
    ct:pal("Rec: ~s", [pretty_print(Rec)]),
    ?match(#wtp{radios = [#wtp_radio{wlans = [#wtp_wlan_config{}|_]}|_]}, Rec),
    ok.

json_to_rec() ->
    [{doc, "Test that turning JSON into WTP config records works as expcted"}].
json_to_rec(Config) ->
    ok = do_json_to_rec(Config, "simple.json"),
    ok = do_json_to_rec(Config, "complex.json"),
    ok.

%% ==============================================
%% Helpers
%% ==============================================

datadir(Config) ->
    proplists:get_value(data_dir, Config).

read_json(Config, FileName) ->
    {ok, Bin} = file:read_file(filename:join(datadir(Config), FileName)),
    ct:pal("Bin: ~p", [Bin]),
    jsx:decode(Bin, [return_maps, {labels, existing_atom}]).

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).

pretty_print(wtp, N) ->
    N = record_info(size, wtp) - 1,
    record_info(fields, wtp);
pretty_print(wtp_radio, N) ->
    N = record_info(size, wtp_radio) - 1,
    record_info(fields, wtp_radio);
pretty_print(wtp_wlan_config, N) ->
    N = record_info(size, wtp_wlan_config) - 1,
    record_info(fields, wtp_wlan_config);
pretty_print(wtp_wlan_rsn, N) ->
    N = record_info(size, wtp_wlan_rsn) - 1,
    record_info(fields, wtp_wlan_rsn);
pretty_print(_, _) ->
    no.
