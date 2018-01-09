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

-module(capwap_config_wtp_provider).

-export([
   get_config/1
]).

-type result() :: {ok, proplists:proplist()} | {error, _Reason}.

-callback get_config(CN :: binary(), _Opts) -> result().

get_config(CN) ->
    get(get_config, [CN]).

get(Fun, Args) ->
    Default = [ capwap_env_config_wtp_provider ],
    Providers = capwap_config:get(ac, config_providers, Default),
    {ok, Result} = lists:foldl(fun(Provider, Acc) ->
        provider_eval(Provider, Fun, Args, Acc)
    end, undefined, Providers),
    Result.

provider_eval(_, _, _, Acc) when Acc /= undefined -> Acc;
provider_eval(Provider, Fun, Args, AccValues) when is_atom(Provider) ->
    provider_eval({Provider, undefined}, Fun, Args, AccValues);
provider_eval({Provider, Opts}, Fun, Args, AccValues) ->
    case catch erlang:apply(Provider, Fun, Args ++ [Opts]) of
        {ok, Settings} ->
            lager:debug("Eval config provider ~p with opts ~p", [Provider, Opts]),
            lager:trace("Get wtp config for ~p => ~p", [Args, Settings]),
            {ok, Settings};
        Error ->
            lager:debug("Error in provider ~p with reason ~p", [Provider, Error]),
            AccValues
    end.
