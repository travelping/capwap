-module(capwap).

-export([list_wtps/0, get_wtp/1]).
-export([list_stations/0, detach_station/1]).

get_wtp(CommonName) ->
    capwap_ac:get_state(CommonName).

list_wtps() ->
    capwap_wtp_reg:list_commonnames().

list_stations() ->
    Stations0 = capwap_station_reg:list_stations(),
    Stations1 = lists:foldl(fun({AC, MAC}, Acc) ->
				    orddict:update(AC, fun(V) -> [MAC|V] end, [MAC], Acc)
			    end, orddict:new(), Stations0),
    lists:map(fun({K, V}) ->
		      [WTP|_] = capwap_wtp_reg:get_commonname(K),
		      {WTP, V}
	      end, orddict:to_list(Stations1)).

detach_station(MAC) ->
    ieee80211_station:detach(MAC).
