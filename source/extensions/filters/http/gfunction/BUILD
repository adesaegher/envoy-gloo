licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_package",
)

envoy_package()

load("@envoy_api//bazel:api_build_system.bzl", "api_proto_library")

#envoy_cc_library(
#    name = "gcloud_authenticator_lib",
#    srcs = ["gcloud_authenticator.cc"],
#    hdrs = ["gcloud_authenticator.h"],
#    external_deps = ["ssl"],
#    repository = "@envoy",
#    deps = [
#        "@envoy//include/envoy/buffer:buffer_interface",
#        "@envoy//include/envoy/http:header_map_interface",
#        "@envoy//source/common/common:assert_lib",
#        "@envoy//source/common/common:empty_string",
#        "@envoy//source/common/common:hex_lib",
#        "@envoy//source/common/config:json_utility_lib",
#        "@envoy//source/common/http:headers_lib",
#        "@envoy//source/common/http:utility_lib",
#    ],
#)

envoy_cc_library(
    name = "gfunction_filter_lib",
    srcs = [
        "gfunction_filter.cc",
    ],
    hdrs = [
        "gfunction_filter.h",
    ],
    repository = "@envoy",
    deps = [
#        ":gcloud_authenticator_lib",
        ":config_lib",
        "//api/envoy/config/filter/http/gfunction/v2:gfunction_proto_cc",
        "//source/common/http:solo_filter_utility_lib",
        "//source/extensions/filters/http:solo_well_known_names",
        "@envoy//source/common/http:utility_lib",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:empty_string",
        "@envoy//source/common/common:hex_lib",
    ],
)

envoy_cc_library(
    name = "config_lib",
    srcs = [
        "config.cc",
    ],
    hdrs = [
        "config.h",
    ],
    repository = "@envoy",
    deps = [
#        ":gcloud_authenticator_lib",
        "//api/envoy/config/filter/http/gfunction/v2:gfunction_proto_cc",
        "//source/common/http:solo_filter_utility_lib",
        "//source/extensions/filters/http:solo_well_known_names",
        "@envoy//source/common/http:utility_lib",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:empty_string",
        "@envoy//source/common/common:hex_lib",
    ],
)

envoy_cc_library(
    name = "gfunction_filter_config_lib",
    srcs = ["gfunction_filter_config_factory.cc"],
    hdrs = ["gfunction_filter_config_factory.h"],
    repository = "@envoy",
    deps = [
        ":gfunction_filter_lib",
        "@envoy//include/envoy/registry",
        "@envoy//source/extensions/filters/http/common:empty_http_filter_config_lib",
    ],
)
