{
  "targets": [
    {
      "target_name": "ushark",
      "variables": {
        "wireshark": "<(module_root_dir)/../wireshark",
        "wlibs": "<(wireshark)/build/run",
      },
      "sources": [
        "bindings/dissector.cpp",
        "bindings/bindings.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        ".",
        "<(wireshark)",
        "<(wireshark)/include",
        "<(wireshark)/build"
      ],
      "defines": [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ],
      "cflags": [
        "<!@(pkgconf --cflags gmodule-2.0 gnutls libgcrypt)"
      ],
      "libraries": [
        "<(module_root_dir)/libushark/libushark.a",
        "<(wlibs)/libwireshark.a",
        "<(wlibs)/libcaputils.a",
        "<(wlibs)/libwiretap.a",
        "<(wlibs)/libversion_info.a",
        "<(wlibs)/libwsutil.a",
        "<(wlibs)/libui.a",
        "<!@(pkgconf --libs gmodule-2.0 gnutls libgcrypt libpcap)"
      ],
    }
  ]
}
