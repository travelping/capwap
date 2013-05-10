-ifdef(debug).

-define(RED,   "\e[01;31m").
-define(GREEN, "\e[01;32m").
-define(BLUE,  "\e[01;34m").
-define(WHITE, "\e[0;37m").

-define(DEBUG(FORMAT, DATA),
        io:format("~w(~B): " ++ (FORMAT) ++ ?WHITE, [?MODULE, ?LINE | DATA])).
-define(DEBUG(FORMAT), ?DEBUG(FORMAT, [])).

-else.

-define(DEBUG(FORMAT, DATA), (false andalso (DATA) orelse ok)).
-define(DEBUG(FORMAT), ok).

-endif.
