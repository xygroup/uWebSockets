# You can use this library as: #include "uWebSockets/uWebSockets.h"
cc_inc_library(
    name = "uWebSockets",
    hdrs = ["src/uWebSockets.h"],
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
    deps = ["//libuv"],
    visibility = ["//visibility:private"],
)
