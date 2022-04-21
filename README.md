capwap - Erlang CAPWAP AC implementation
========================================
[![Build Status][gh badge]][gh]
[![Coverage Status][coveralls badge]][coveralls]
[![Erlang Versions][erlang version badge]][gh]
[![Docker][docker badge]][docker]

Erlang CAPWAP AC implementation.

[capwap certificate requirements](docs/certificates.md)

[http api](docs/http_api.md)

[configuration providers for WTPs](docs/wtp_config_providers.md)

[metrics](docs/metrics.md)

BUILDING
--------

*The minimum supported Erlang version is 24.2.*

Using rebar:

    # rebar3 compile

<!-- Badges -->
[gh]: https://github.com/travelping/capwap/actions/workflows/main.yml
[gh badge]: https://img.shields.io/github/workflow/status/travelping/capwap/CI?style=flat-square
[coveralls]: https://coveralls.io/github/travelping/capwap
[coveralls badge]: https://img.shields.io/coveralls/travelping/capwap/master.svg?style=flat-square
[erlang version badge]: https://img.shields.io/badge/erlang-24.2%20to%2024.3-blue.svg?style=flat-square
[docker]: https://github.com/travelping/capwap/actions/workflows/docker.yaml
[docker badge]: https://github.com/travelping/capwap/actions/workflows/docker.yaml/badge.svg
