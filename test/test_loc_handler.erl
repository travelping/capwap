-module(test_loc_handler).

-export([init/2]).

init(Req0, State) ->
    ct:pal("Receiving request in test_loc_handler: ~p~n", [Req0]),
    Resp = cowboy_req:reply(200,
        #{<<"content-type">> => <<"application/json">>},
        jsx:encode(#{
          <<"TB_Telemetry_Latitude">> => [#{<<"ts">> => 1644616748053, <<"value">> => <<"52.110949">>}],
          <<"TB_Telemetry_Longitude">> => [#{<<"ts">> => 1644616748053, <<"value">> => <<"11.625512">>}]}),
        Req0),
    {ok, Resp, State}.