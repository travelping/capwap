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

-module(capwap_http_config_wtp_provider).
-behaviour(capwap_config_wtp_provider).

-export([
   get_config/2
]).

-define(DEFAULT_HTTP, "http://127.0.0.1").

get_config(CN, undefined) ->
    get_config(CN, ?DEFAULT_HTTP);
get_config(CN, Opts) ->
    JSON = request(<<"/", CN/binary>>, Opts),
    validate_config(JSON),
    Config = proplists:get_value(config, JSON, []),
    Res = lists:map(fun transform_value/1, Config),
    {ok, Res}.

request(Path, Opts) ->
    HttpServer = list_to_binary(Opts),
    Http = <<HttpServer/binary, Path/binary>>,
    {ok, 200, _Headers, ClientRef} = hackney:request(get, Http, []),
    {ok, Body} = hackney:body(ClientRef),
    jsx:decode(Body, [{labels, atom}]).

validate_config(JSON) ->
    <<"wtp-config">> = proplists:get_value(type, JSON),
    <<"1.0">> = proplists:get_value(version, JSON).

transform_value({operation_mode, V}) ->
    {operation_mod, erlang:binary_to_atom(V, utf8)};
transform_value({short_preamble, V}) ->
    {short_preambl, erlang:binary_to_atom(V, utf8)};
transform_value({channel_assessment, V}) ->
    {channel_assessment, erlang:binary_to_atom(V, utf8)};
transform_value({diversity, V}) ->
    {diversity, erlang:binary_to_atom(V, utf8)};
transform_value({combiner, V}) ->
    {combiner, erlang:binary_to_atom(V, utf8)};
transform_value({radio, Radios}) ->
    {radio, [ lists:map(fun transform_value/1, Radio) || Radio <- Radios ]};
transform_value(Other) -> Other.
