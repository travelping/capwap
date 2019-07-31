DHCP RELAY
==========

CapwapAC has DHCP relay for receive DHCP client broadcasts and transmits it to
DHCP Servers.

 +-------+
 |Clients|
 ++------+
  |WIFI
  |  +----------+
  +->|WTP Router|
     +-+--------+
       |CAPWAP
       |    +---------+         +---------+        +-----------+
       +--->|CAPWAP DP|         |CAPWAP AC|        |DHCP Server|
            +---------+         +---------+        +-----------+
               :67 |<---------------->|                   |
                        DHCP packets  |                   |
                                EXTERNAL_IP:67 <--------->|:68
                                                DHCP packets

DHCP Relay config
-----------------
```erlang
[{capwap,
    {dhcp_relay, [
        {external_ip, {192,168,86,10}},
        {servers, [{192,168,81,1}]},
        {remote_id, [<<"User">>, 'Username', <<"END">>]},
        {circuit_id, [<<"BSSID">>, 'BSSID', <<"END">>]},
        {agent_id, [<<"AgentID">>]}
    ]},
    ...
]
```

If this section not present in config DHCP Relay will be disabled.
