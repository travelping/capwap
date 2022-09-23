%% Copyright 2017-2019 Travelping GmbH <info@travelping.com>
%%
%% This program is free software: you can redistribute it and/or modify
%% it under the terms of the GNU Lesser General Public License as
%% published by the Free Software Foundation, either version 3 of the
%% License, or (at your option) any later version.
%%
%% This program is distributed in the hope that it will be useful,
%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
%% GNU Lesser General Public License for more details.
%%
%% You should have received a copy of the GNU Lesser General Public License
%% along with this program. If not, see <http://www.gnu.org/licenses/>.

-module(capwap_loc_provider_http).

-compile({parse_transform, cut}).

-behaviour(capwap_loc_provider).

%% AAA API
-export([config_fun/1]).

-include_lib("kernel/include/logger.hrl").

-define(LAT_KEY, <<"latitude">>).
-define(LONG_KEY, <<"longitude">>).

config_fun(#{uri := Uri, timeout := Timeout}) ->
  ParsedUri = uri_string:parse(Uri),
  fun(Name) -> resolve_loc_http(ParsedUri, Timeout, Name) end.

resolve_loc_http(Uri, Timeout, Name) ->
    ?LOG(debug, "HTTP provider towards: ~p", [Uri]),
    #{path := UriPath} = Uri,
    JsonHeader = {<<"Content-Type">>, <<"application/json">>},
    UriPathBin = unicode:characters_to_binary(UriPath),
    ?LOG(debug, "UriPathBin: ~p", [UriPathBin]),
    CompletePath = <<UriPathBin/binary, "/location/", Name/binary>>,
    CompleteUri = Uri#{path => CompletePath},
    case http_request(uri_string:recompose(CompleteUri), [JsonHeader], [{timeout, Timeout}]) of
        {ok, {Response = #{?LAT_KEY := LatVal, ?LONG_KEY := LongVal}, _LocReqState}} ->
            ?LOG(debug, "Got response: ~p", [Response]),
            {location, LatVal, LongVal};
        {ok, {Response, _LocReqState}} ->
            ?LOG(error, "Got non-matching response: ~p", [Response]),
            {error, {response_format, Response}};
        {error, Error} ->
            ?LOG(error, "Error retrieving location: ~p", [Error]),
            {error, {http_error, Error}}
    end.


http_request(Http, Headers, Opts) ->
  case hackney:request(get, Http, Headers, <<>>, Opts) of
    {ok, 200, _RespHeaders, ClientRef} ->
      {ok, Body} = hackney:body(ClientRef),
      {ok, {jsx:decode(Body, [return_maps]), ClientRef}};
    Error ->
      % exometer:update([capwap, ac, error_wtp_http_config_count], 1),
      {error, Error}
  end.