METRICS
=======

The following metrics exist:

| Metric                                                               | Type      |
| -------------------------------------------------------------------- | --------- |
| capwap.ac.station\_count                                             | counter   |
| capwap.ac.wtp\_count                                                 | counter   |
| capwap.ac.ssl\_expired\_certs\_count                                 | counter   |
| capwap.ac.error\_wtp\_http\_config\_count                            | counter   |
| capwap.dp.\<Id\>.Error-Fragrent-Invalid                              | gauge     |
| capwap.dp.\<Id\>.Error-Fragment-Too-Old                              | gauge     |
| capwap.dp.\<Id\>.Error-Header-Length-Invalid                         | gauge     |
| capwap.dp.\<Id\>.Error-Invalid-Stations                              | gauge     |
| capwap.dp.\<Id\>.Error-Invalid-WTP                                   | gauge     |
| capwap.dp.\<Id\>.Error-Too-Short                                     | gauge     |
| capwap.dp.\<Id\>.InOctets                                            | gauge     |
| capwap.dp.\<Id\>.InPackets                                           | gauge     |
| capwap.dp.\<Id\>.OutOctets                                           | gauge     |
| capwap.dp.\<Id\>.OutPackets                                          | gauge     |
| capwap.dp.\<Id\>.Rate-Limit-Unknown-WTP                              | gauge     |
| capwap.dp.\<Id\>.Received-Fragments                                  | gauge     |
| capwap.dp.\<Id\>.Send-Fragments                                      | gauge     |
| capwap.wtp.\<WtpId\>.Error-Fragment-Invalid                          | gauge     |
| capwap.wtp.\<WtpId\>.Error-Fragment-Too-Old                          | gauge     |
| capwap.wtp.\<WtpId\>.Error-Invalid-Stations                          | gauge     |
| capwap.wtp.\<WtpId\>.InOctets                                        | gauge     |
| capwap.wtp.\<WtpId\>.InPackets                                       | gauge     |
| capwap.wtp.\<WtpId\>.OutOctets                                       | gauge     |
| capwap.wtp.\<WtpId\>.OutPackets                                      | gauge     |
| capwap.wtp.\<WtpId\>.Received-Fragments                              | gauge     |
| capwap.wtp.\<WtpId\>.Send-Fragments                                  | gauge     |
| capwap.wtp.\<WtpId\>.start\_time                                     | gauge     |
| capwap.wtp.\<WtpId\>.station\_count                                  | gauge     |
| capwap.wtp.\<WtpId\>.stop\_time                                      | gauge     |


If the HTTP API has been enable the metrics can be read at `/metrics`.
Stepping into the result is also possible, e.g.:

    curl -X GET "http://localhost:8000/metrics/capwap/ac/wtp_count" -H  "accept: application/json"

Also, capwap can provide metrics in Prometheus format:

    curl -X GET "http://localhost:8000/metrics" -H  "accept: text/plain;version=0.0.4"

Please read [Metric names and labels](https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels)
that means all '.' and '-' in metric names which presented above will be replaced by '_'.
