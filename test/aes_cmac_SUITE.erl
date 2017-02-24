%% Copyright (C) 2017, Travelping GmbH <info@travelping.com>

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

-module(aes_cmac_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").

-define(equal(Expected, Actual),
    (fun (Expected@@@, Expected@@@) -> true;
         (Expected@@@, Actual@@@) ->
             ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
                    [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
             false
     end)(Expected, Actual) orelse error(badmatch)).


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

do_aes_cmac([]) ->
    ok;
do_aes_cmac([{Key, Data, Expected} | Next]) ->
    CMAC = aes_cmac:aes_cmac(Key, Data),
    ?equal(Expected, CMAC),
    do_aes_cmac(Next).

test_aes_cmac(_Config) ->
    Key = hexstr2bin("2B7E151628AED2A6ABF7158809CF4F3C"),
    Cases = [{Key,
	      <<"">>,
	      hexstr2bin("bb1d6929e95937287fa37d129b756746")},
	     {Key,
	      hexstr2bin("6bc1bee22e409f96e93d7e117393172a"),
	      hexstr2bin("070a16b46b4d4144f79bdd9dd04a287c")},
	     {Key,
	      hexstr2bin("6bc1bee22e409f96e93d7e117393172a"
			 "ae2d8a571e03ac9c9eb76fac45af8e51"
			 "30c81c46a35ce411"),
	      hexstr2bin("dfa66747de9ae63030ca32611497c827")},
	     {Key,
	      hexstr2bin("6bc1bee22e409f96e93d7e117393172a"
			 "ae2d8a571e03ac9c9eb76fac45af8e51"
			 "30c81c46a35ce411e5fbc1191a0a52ef"
			 "f69f2445df4f9b17ad2b417be66c3710"),
	      hexstr2bin("51f0bebf7e3b9d92fc49741779363cfe")}],
    do_aes_cmac(Cases).

all() ->
    [test_aes_cmac].

init_per_suite(Config) ->
	Config.

end_per_suite(_Config) ->
	ok.

