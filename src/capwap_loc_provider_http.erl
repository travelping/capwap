%% Copyright (C) 2023, Travelping GmbH <info@travelping.com>
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

-behaviour(capwap_loc_provider).

-export([config_fun/1, validate_provider/1]).

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
    CompleteUri = Uri#{path => iolist_to_binary([UriPath, <<"/location/">>, Name])},
    case http_request(uri_string:recompose(CompleteUri), [JsonHeader], [{timeout, Timeout}]) of
	{ok, Response = #{?LAT_KEY := LatVal, ?LONG_KEY := LongVal}} ->
	    ?LOG(debug, "Got response: ~p", [Response]),
	    {location, LatVal, LongVal};
	{ok, Response} ->
	    ?LOG(error, "Got non-matching response: ~p", [Response]),
	    {error, {response_format, Response}};
	{error, Error} ->
	    ?LOG(error, "Error retrieving location: ~p", [Error]),
	    {error, {http_error, Error}}
    end.

% Body option is set here because it is handled here
http_request(Http, Headers, Opts) ->
    case hackney:request(get, Http, Headers, <<>>, Opts ++ [{with_body, true}]) of
	{ok, 200, _RespHeaders, Body} ->
	    try {ok, jsx:decode(Body, [return_maps])}
	    catch error:badarg -> {error, {json_format_error, Body}} end;
	Error ->
	    {error, Error}
    end.

validate_provider(#{uri := Uri, timeout := Timeout}) when is_number(Timeout) andalso Timeout>0 ->
    #{scheme := Scheme, host := _} = uri_string:parse(Uri),
    case Scheme of
	"http" -> ok;
	"https" -> ok;
	<<"http">> -> ok;
	<<"https">> -> ok
    end,
    ok.
