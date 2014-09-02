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
	Class:Error ->
	    io:format("ERROR(~s:~b)~nCase: ~p~nExpected: ~p~nError: ~p:~p at ~p~n",
		    [?FILE, ?LINE, Perm, Result, Class, Error, erlang:get_stacktrace()]),
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
