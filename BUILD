# You can use this library as: #include "uWebSockets/uWS.h"
cc_inc_library(
    name = "uWebSockets",
    hdrs = glob([
        "src/*.h",
    ]),
    prefix = "src",
    deps = [":uWebSockets_impl"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "uWebSockets_impl",
    srcs = glob([
        "src/*.h",
        "src/*.cpp",
    ]),
    copts = [
        "-stdlib=libc++",
        "-std=c++14",
        "-DBAZEL",
        "-DNO_OPENSSL",
    ],
    deps = [
        "//libuv",
        "//sha1",
        "@zlib//:zlib",
    ],
    linkstatic = 1,
    visibility = ["//visibility:private"],
)

cc_binary(
    name = "echo",
    srcs = ["examples/echo.cpp"],
    copts = [
        "-DBAZEL",
        "-DNO_OPENSSL",
    ],
    deps = [
        ":uWebSockets",
    ],
)

cc_binary(
    name = "client_echo",
    srcs = ["examples/client_echo.cpp"],
    copts = [
        "-DBAZEL",
        "-DNO_OPENSSL",
    ],
    deps = [
        ":uWebSockets",
    ],
)
