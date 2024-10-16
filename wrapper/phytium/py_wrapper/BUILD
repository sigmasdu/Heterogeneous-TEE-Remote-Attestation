package(default_visibility = ["//visibility:public"])
load("@pybind11_bazel//:build_defs.bzl", "pybind_extension")

# link context
pybind_extension(
  name = "phytium_attestation",
  srcs = [
    "wrapper.cc",
    "wrapper.h",
  ],
  deps = [
    "@com_github_jinzhao//:attestation",
  ],
  linkopts = [
    "-ldl",
    "-lprotobuf"
  ],
)

py_library(
  name = "phytium_attestation",
  data = ["phytium_attestation.so"],
)
