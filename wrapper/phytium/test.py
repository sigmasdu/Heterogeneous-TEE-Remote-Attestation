#!/usr/bin/env python3
import sys
sys.path.insert(0, "./bazel-bin/py_wrapper")
print(sys.path)
import phytium_attestation as phy

#generate csr
csr_content = phy.gen_csr("test", "test") 
print("XXXXXXXX show csr")
print(csr_content)
print("\n\n")
report_bytes, policy_bytes = phy.generate_report()

print("XXXXXXXX show report")
print(report_bytes)
print("\n\n")
print("XXXXXXXX show policy")
print(policy_bytes)
print("\n\n")

print("begin to verify report using policy......")
phy.verify_report(report_bytes, policy_bytes)
print("verify report using policy successfully ")
print("\n\n")
