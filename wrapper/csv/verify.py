import sys
sys.path.append(".")

import csv_wrap

with open("report.bin", 'rb') as fd:
    report = fd.read()

with open("policy.bin", "rb") as fd:
    policy = fd.read()


if not csv_wrap.verify_csv_proof(report, policy):
    print("verify csv finished")
else:
    print("verify csv failed")
