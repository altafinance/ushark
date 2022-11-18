{
  "targets": [
    {
      "target_name": "ushark",
      "variables": {
        "wireshark": "<(module_root_dir)/wireshark-static",
        "wlibs": "<(wireshark)/libs",
      },
      "sources": [
        "libushark/ushark.c",
        "wireshark-static/frame_tvbuff.c",
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
        "<(wlibs)/libwireshark.a",
        "<(wlibs)/libcaputils.a",
        "<(wlibs)/libwiretap.a",
        "<(wlibs)/libversion_info.a",
        "<(wlibs)/libwsutil.a",
        "<(wlibs)/libui.a",
        "<!@(pkgconf --libs glib-2.0 gmodule-2.0 gnutls libgcrypt libpcre2-8 zlib libbrotlidec \
          libzstd gpg-error liblz4 libnghttp2 libcares snappy libpcap) -lm"
      ],
    }
  ]
}
