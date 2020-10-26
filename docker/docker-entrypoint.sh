#!/bin/sh
# copy of configuration files
RELPATH=$(find /opt/ergw-capwap-node/releases/ -mindepth 1 -maxdepth 1 -type d)
[ -f /config/ergw-capwap-node/sys.config ] && cp /config/ergw-capwap-node/sys.config $RELPATH/sys.config
[ -f /config/ergw-capwap-node/vm.args ] && cp /config/ergw-capwap-node/vm.args $RELPATH/vm.args

exec "$@"
