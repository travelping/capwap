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

-module(capwap_stream).

-export([init/1, set_mtu/2, get_mtu/1, recv/3, encode/3]).

%% export for test suite
-export([add/2]).

-include_lib("kernel/include/logger.hrl").
-include("capwap_packet.hrl").

-define(MAX_FRAGMENTS, 32).

-record(part, {pstart, pend, payload}).
-record(buffer, {
                 fragmentid :: integer(),
                 header     :: #capwap_header{},
                 length     :: 'undefined' | integer(),
                 data       :: [#part{}]
                }).

-record(stream, {
                 %% recv handling
                 base = 0 :: non_neg_integer(),
                 buffer   :: array:array(#buffer{}),
                 %% send handling
                 mtu = 1500      :: non_neg_integer(),
                 fragment_id = 0 :: non_neg_integer()
                }).

%%%===================================================================
%%% API
%%%===================================================================

init(MTU) ->
    #stream{buffer = array:new(?MAX_FRAGMENTS), mtu = MTU}.

set_mtu(State, MTU) when is_record(State, stream) ->
    State#stream{mtu = MTU}.

get_mtu(#stream{mtu = MTU}) ->
    MTU.

recv(Type, Data, State0) ->
    try capwap_packet:decode(Type, Data) of
        {Header, Msg} when is_record(Header, capwap_header) ->
            {ok, {Header, Msg}, State0};

        Fragment when is_record(Fragment, fragment) ->
            case add(Fragment, State0) of
                {{Header, BinMsg}, State1} ->
                    try capwap_packet:decode(Type, Header, BinMsg) of
                        {Header, Msg} ->
                            {ok, {Header, Msg}, State1}

                    catch
                        _Class:Error:Stack ->
                            {error, {Error, Stack}}
                    end;

                {_, State1} ->
                    {ok, more, State1}
            end
    catch
        _Class:Error:Stack ->
            {error, {Error, Stack}}
    end.

encode(Type, Msg, State = #stream{mtu = MTU, fragment_id = FragId}) ->
    Data = capwap_packet:encode(Type, Msg, FragId, MTU),
    if length(Data) > 1 ->
            %% we did fragment, inc the FragmentId
            {Data, State#stream{fragment_id = (FragId + 1) rem 16#10000}};
       true ->
            {Data, State}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

add(#fragment{fragmentid = FragmentId}, State = #stream{base = Base})
  when ((FragmentId > Base) andalso (FragmentId - Base >= 16#8000)) orelse
       ((FragmentId < Base) andalso ((FragmentId + 16#10000) - Base >= 16#8000)) ->
    %% too old, ignore
    ?LOG(warning, "fragment ~w out of current range ~w", [FragmentId, Base]),
    {[], State};

add(Fragment = #fragment{fragmentid = FragmentId}, State0) ->
    State1 = adjust_fragment_window(FragmentId, State0),
    B0 = get_slot(Fragment, State1),
    case add_fragment(Fragment, B0) of
        {more, B1} ->
            State2 = set_slot(B1, State1),
            {[], State2};
        {complete, Data} ->
            {{B0#buffer.header, Data}, State1#stream{base = State1#stream.base + 1}}
    end.

%% advance base to be in the MAX_FRAGMENTS window if needed
adjust_fragment_window(FragmentId, State = #stream{base = Base})
  when FragmentId < Base ->
    adjust_fragment_window(FragmentId + 16#10000, State);
adjust_fragment_window(FragmentId, State = #stream{base = Base})
  when FragmentId - Base > ?MAX_FRAGMENTS ->
    State#stream{base = FragmentId - ?MAX_FRAGMENTS};
adjust_fragment_window(_FragmentId, State) ->
    State.

get_slot(#fragment{fragmentid = FragmentId, header = Header}, #stream{buffer = Buffer}) ->
    case array:get(FragmentId rem ?MAX_FRAGMENTS, Buffer) of
        Value = #buffer{fragmentid = FragmentId} ->
            Value;
        _ ->
            #buffer{fragmentid = FragmentId, header = Header, data = []}
    end.

set_slot(Value = #buffer{fragmentid = FragmentId}, State = #stream{buffer = Buffer}) ->
    State#stream{buffer = array:set(FragmentId rem ?MAX_FRAGMENTS, Value, Buffer)}.

handle_buffer_data([#part{pstart = 0, pend = Length, payload = Data}], #buffer{length = Length}) ->
    {complete, Data};
handle_buffer_data(DataOut, Buffer) ->
    {more, Buffer#buffer{data = DataOut}}.

add_fragment(Fragment = #fragment{header = Header, last = Last},
             Buffer0 = #buffer{header = Header, data = DataIn}) ->
    case add_part(to_part(Fragment), DataIn, []) of
        DataOut when is_list(DataOut) ->
            Buffer1 = if Last -> Buffer0#buffer{length = Fragment#fragment.fend};
                         true -> Buffer0
                      end,
            handle_buffer_data(DataOut, Buffer1);
        Other ->
            ?LOG(warning, "unable to process fragment: ~p", [Other]),
            {more, Buffer0}
    end;

add_fragment(#fragment{fragmentid = FragmentId, header = FHeader},
             Buffer = #buffer{header = BHeader}) ->
    ?LOG(error, "Fragment ~w, have header: ~p, got header ~p", [FragmentId, FHeader, BHeader]),
    {more, Buffer}.

to_part(#fragment{fstart = Start, fend = End, payload = Data}) ->
    #part{pstart = Start, pend = End, payload = Data}.

-define(in_range_s(V, Start, End), (((V) >= (Start)) andalso ((V) < (End)))).
-define(in_range_e(V, Start, End), (((V) > (Start)) andalso ((V) =< (End)))).

-define(overlap(S1, E1, S2, E2), (?in_range_s(S1, S2, E2) orelse ?in_range_e(E1, S2, E2) orelse
                                  ?in_range_s(S2, S1, E1) orelse ?in_range_e(E2, S1, E1))).


%% first element in append to list
add_part(#part{pstart = FStart, pend = FEnd, payload = PayLoad}, [], Result) ->
    lists:reverse([#part{pstart = FStart, pend = FEnd, payload = PayLoad}|Result]);

%% check for overlap
add_part(#part{pstart = FStart, pend = FEnd},
         [#part{pstart = PStart, pend = PEnd}|_], _)
  when ?overlap(PStart, PEnd, FStart, FEnd) ->
    ?LOG(error, "overlap: ~w, ~w, ~w, ~w", [PStart, PEnd, FStart, FEnd]),
    {error, overlap};

%% append to current part
add_part(#part{pstart = FStart, pend = FEnd, payload = FData},
         [#part{pstart = PStart, pend = PEnd, payload = PData}|Tail], Result)
  when PEnd == FStart ->
    New = #part{pstart = PStart, pend = FEnd, payload = <<PData/binary, FData/binary>>},
    add_part(New, Tail, Result);

%% prepend to current part
add_part(#part{pstart = FStart, pend = FEnd, payload = FData},
         [#part{pstart = PStart, pend = PEnd, payload = PData}|Tail], Result)
  when PStart == FEnd ->
    New = #part{pstart = FStart, pend = PEnd, payload = <<FData/binary, PData/binary>>},
    lists:reverse([New|Result]) ++ Tail;

%% insert before current part
add_part(#part{pstart = FStart, pend = FEnd, payload = FData},
         [Head = #part{pstart = PStart}|Tail], Result)
  when PStart > FStart ->
    New = #part{pstart = FStart, pend = FEnd, payload = FData},
    lists:reverse([Head,New|Result]) ++ Tail;

%% next
add_part(New, [Head|Tail], Result) ->
    add_part(New, Tail, [Head|Result]).
