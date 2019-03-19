%% Copyright (C) 2013-2019, Travelping GmbH <info@travelping.com>

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

-module(capwap_http_api_v2_handler).

-export([handle/4]).

%%%===================================================================
%%% API
%%%===================================================================

handle(<<"GET">>, [<<"station">>], Req, State) ->
    Stations = capwap:list_stations(),
    Res = lists:map(fun format_wtps/1, Stations),
    {jsx:encode(Res), Req, State};

handle(<<"DELETE">>, [<<"wtp">>, _WTP, <<"station">>, Station], Req, State) ->
    case capwap_tools:mac_to_hex(Station) of
        MACSta when is_binary(MACSta) ->
            case capwap:detach_station(MACSta) of
                ok ->
                    {true, Req, State};
                _ ->
                    {false, Req, State}
            end;
        _ ->
            {false, Req, State}
    end;

handle(_Method, _Path, Req, State) ->
    {jsx:encode([{error, bad_command}]), Req, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

format_wtps({{WTP, _WtpIP}, STAs}) ->
    Radios = lists:foldl(fun format_radios/2, #{}, STAs),

    ResRadios = maps:fold(
        fun(RadioId, STAs0, Acc) ->
            [[{'radio-id', RadioId},
              {stations, STAs0}] | Acc]
        end,
        [], Radios),
    [[{'wtp-id', WTP},
      {radios, ResRadios}]].

format_radios(ClientMAC, Acc) ->
    case get_station_statistic(ClientMAC) of
        {RadioId, Stats} ->
           update_radio(RadioId,
             [
               {mac, bin_fmt("~s", [capwap_tools:format_mac(ClientMAC)])}
             ] ++ Stats, Acc);
        _ -> Acc
    end.

get_station_statistic(MAC) ->
    case capwap_dp:get_station(MAC) of
        {_MAC, VLan, RadioId, _BSS,
           {RcvdPkts, SendPkts, RcvdBytes, SendBytes, RSSI, _SNR, _DR}} ->
             {RadioId, [{vlan, VLan},
                        {'rx-packets', RcvdPkts},
                        {'rx-bytes', RcvdBytes},
                        {'tx-packets', SendPkts},
                        {'tx-bytes', SendBytes},
                        {rssi, RSSI}
                       ]};
        _ ->
             undefined
    end.

update_radio(Id, Station, Acc) ->
    maps:update_with(Id, fun(Stations) -> [Station|Stations] end, [Station], Acc).

bin_fmt(FmtStr, Args) ->
    erlang:list_to_binary(io_lib:format(FmtStr, Args)).
