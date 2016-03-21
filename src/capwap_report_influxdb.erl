-module(capwap_report_influxdb).

-export([subscribe/2]).

subscribe([capwap, wtp, _WTP, _Value] = Metric, gauge) ->
    Tags = [{type,     {from_name, 1}},
	    {category, {from_name, 2}},
	    {wtp,      {from_name, 3}}],
    Extra = [{tags, Tags}],
    {Metric, value, 30000, Extra};

subscribe([capwap, ac, _Value] = Metric, _) ->
    Tags = [{type,     {from_name, 1}},
	    {category, {from_name, 2}}],
    Extra = [{tags, Tags}],
    {Metric, value, 30000, Extra};

subscribe(_, _) -> [].
