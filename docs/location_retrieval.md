LOCATION RETRIEVAL USING AN HTTP ENDPOINT
=========================================

CAPWAP includes an `ergw_aaa` handler to perform an HTTP
request and fill in the `IM_LI_Location` AVP previous to
performing RADIUS requests. To include this functionality,
the new handler has to be provisioned in the `ergw_aaa` section
of the erlang configuration file, a new service using the handler
need to be defined, and the service included **in the right
order** in the list of steps for the appropriate procedure.
An example configuration is shown here:

```erlang
{ergw_aaa, [
  {handlers, [
    ...
    {capwap_http_loc, [
    ]}
  ]},
  {services, [
    ...
    {'Load-Location', [
      {timeout, 5000},
      {uri, "https://127.0.0.1:9999/api/v1/sOmEtOkEn/attributes"},
      {keys, [{lat_key, "TB_Telemetry_Latitude"}, {long_key, "TB_Telemetry_Longitude"}]},
      {handler, capwap_http_loc}]},
  ]},
  {apps, [
    ...
    {capwap_station, [
      {session, ['Default']},
      {procedures, [
        {authenticate, ['Load-Location', 'RADIUS-Auth-Station']},
        {authorize, []},
        {start,   ['Load-Location', 'RADIUS-Acct-Station']},
        {interim, ['Load-Location', 'RADIUS-Acct-Station']},
        {stop,    ['Load-Location', 'RADIUS-Acct-Station']}
      ]}
    ]},
  ]},
  ...
]}.  
```

Configuration Items
-------------------

The different configuration items to be specified in the
`service` section are described below:

* `timeout` : HTTP connection timeout
* `uri` : base URI to which the request will be sent. A query is
appended to this URI.
* `keys` : list of keys to be requested to compose the location attribute.
The current keys used are "TB_Telemetry_Latitude" (for the latitude value)
and "TB_Telemetry_Longitude" (for the longitude value). Both values are expected
in decimal format, and will be composed into the AVP as the string
`Lat:LATITUDE;Lon:LONGITUDE`.
The query composed has the form `http://base/uri?keys={lat_key},{long_key}`
* `handler` : the name of the handler used (always `capwap_http_loc`).
