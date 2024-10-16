cc_binary(
  name = "generator",
  srcs = [
    "app.h",
    "app.cc",
  ],
  deps = [
    "@com_github_jinzhao//:attestation",
  ],
  linkopts = [
    "-luniattest",
    "-ldl",
    "-lprotobuf"
  ],
)

cc_binary(
  name = "verfify",
  srcs = [
    "verify.cc",
    "verify.h",
  ],
  deps = [
    "@com_github_jinzhao//:attestation",
  ],
  linkopts = [
    "-ldl",
    "-lprotobuf"
  ],
)
