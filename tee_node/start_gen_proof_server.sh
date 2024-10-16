#!/bin/bash
if (($# != 1)); then
  echo "which tee type proof gen server do you want to start"
  echo "available tee: phytium|sgx|csv"
  exit -1
fi
tee_type=$1
if [[ "$tee_type" == "phytium" ]]; then
  source /data/env.source
  python3 phytium_node.py --config phytium_config.json
elif [[ "$tee_type" == "sgx" ]]; then
  python3 sgx_node.py --config sgx_config.json
elif [[ "$tee_type" == "csv" ]]; then
  pushd csv
  python3 hygon_csv_node.py --config hygon_csv_config.json
else
  echo "unsupported tee type: [${tee_type}]"
fi
