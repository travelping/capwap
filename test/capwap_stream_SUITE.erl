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

-module(capwap_stream_SUITE).
-compile(export_all).

-include("../include/capwap_packet.hrl").

all() -> [reassemble].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

                                                % --------------------------------------------------------------------------------------------------
                                                % -- test cases

reassemble(_Config) ->
    Cases = [{iolist_to_binary(X), perms(l2frags(X))} || X <- perms(parts(5))],
    run_cases(Cases).

run_cases([]) ->
    ok;
run_cases([{Result, Perm}|Tail]) ->
    run_case_permutations(Result, Perm),
    run_cases(Tail).

run_case_permutations(_, []) ->
    ok;
run_case_permutations(Result, [Head|Tail]) ->
    run_permutation(Result, Head),
    run_case_permutations(Result, Tail).

run_permutation(Result, Perm) ->
    S0 = capwap_stream:init(1500),
    try lists:foldl(fun(X, {_, S}) -> capwap_stream:add(X, S) end, {[], S0}, Perm) of
        {{_, Result}, _} -> ok;
        V -> ct:fail("MISMATCH(~s:~b)~nCase: ~p~nExpected: ~p~nActual: ~p~n",
                     [?FILE, ?LINE, Perm, Result, V]),
             error(badmatch)
    catch
        Class:Error:Stack ->
            io:format("ERROR(~s:~b)~nCase: ~p~nExpected: ~p~nError: ~p:~p at ~p~n",
                      [?FILE, ?LINE, Perm, Result, Class, Error, Stack]),
            error(Error)
    end.

                                                % --------------------------------------------------------------------------------------------------
                                                % -- helper

parts(N) ->
    parts(N, []).

parts(0, Acc) ->
    Acc;
parts(N, Acc) ->
    parts(N - 1, [list_to_binary(lists:duplicate(N, N))|Acc]).

l2frags(List) ->
    l2frags(List, 0, []).

l2frags(L = [Head], Pos, Acc) when length(L) == 1 ->
    F = {fragment, control, false, 1, Pos, Pos + size(Head), true, undefined, Head},
    lists:reverse([F|Acc]);
l2frags([Head|Tail], Pos, Acc) ->
    F = {fragment, control, false, 1, Pos, Pos + size(Head), false, undefined, Head},
    l2frags(Tail, Pos + size(Head), [F|Acc]).

perms([]) -> [[]];
perms(L)  -> [[H|T] || H <- L, T <- perms(L--[H])].
