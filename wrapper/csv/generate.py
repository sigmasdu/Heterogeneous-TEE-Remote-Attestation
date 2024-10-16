import sys 
sys.path.append(".")

import csv_wrap
report, policy = csv_wrap.gen_csv_proof()
#print(report)
#print(policy)
print("$$$"*20)
with open("report.bin", "wb") as fd:
    fd.write(report)
with open("policy.bin", "wb") as fd:
    fd.write(policy)
#csv_wrap.verify_csv_proof(report, policy)
