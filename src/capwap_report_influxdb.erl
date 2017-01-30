%% Copyright (C) 2013-2017, Travelping GmbH <info@travelping.com>

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

subscribe([capwap, dp, _Thread, _Value] = Metric, _) ->
    Tags = [{type,     {from_name, 1}},
	    {category, {from_name, 2}},
	    {thread,   {from_name, 3}}],
    Extra = [{tags, Tags}],
    {Metric, value, 30000, Extra};

subscribe(_, _) -> [].
