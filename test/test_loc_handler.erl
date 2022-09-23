-module(test_loc_handler).

-export([init/2, content/0]).

init(Req0 = #{path_info := [<<"location">> | _]}, State) ->
    ct:pal("Receiving request in test_loc_handler: ~p~n", [Req0]),
    Resp = cowboy_req:reply(200,
        #{<<"content-type">> => <<"application/json">>},
        test_loc_handler:content(),
        Req0),
    ct:pal("Sending response in test_loc_handler: ~p~n", [Resp]),
    {ok, Resp, State}.

%% Hook for meck
content() ->
  jsx:encode(#{<<"latitude">> => <<"11111">>,  <<"longitude">> => <<"22222">>}).
