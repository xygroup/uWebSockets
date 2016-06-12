# You can use this library as: #include "uWebSockets/uWS.h"
cc_inc_library(
    name = "uWebSockets",
    hdrs = ["src/uWS.h"],
    prefix = "src",
    deps = [":uWebSockets_impl"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "uWebSockets_impl",
    srcs = ["src/uWS.cpp"],
    hdrs = ["src/uWS.h"],
    copts = [
        "-stdlib=libc++",
        "-std=c++14",
        "-DBAZEL=1",
        "-DNO_OPENSSL",
    ],
    deps = ["//libuv", "//sha1"],
    visibility = ["//visibility:private"],
)

cc_binary(
    name = "main",
    srcs = ["main.cpp"],
    deps = [
        ":uWebSockets",
    ],
)

