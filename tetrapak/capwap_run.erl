-module(capwap_run).

-task({"run:capwap", "Start CAPWAP"}).

run("run:capwap", _) ->
    tetrapak:require("build:erlang"),
    [ok = application:start(App) || App <- [sasl, regine, crypto, public_key, ssl, capwap]],
    ok.
