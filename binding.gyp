{
  "targets": [
    {
      "target_name": "ushark",
      "variables": {
        "wireshark": "<(module_root_dir)/../wireshark",
        "wlibs": "<(wireshark)/build/run",
      },
      "sources": [
        "libushark/ushark.c",
        "../wireshark/frame_tvbuff.c",
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
      "defines": [
        'NAPI_DISABLE_CPP_EXCEPTIONS',
        "NAPI_VERSION=<(napi_build_version)"
      ],
      "xcode_settings": {  # These are required for macOS
		"OTHER_CFLAGS": [
		  "<!@(pkg-config --cflags gmodule-2.0 gnutls libgcrypt glib-2.0)"
        ],
        "OTHER_LDFLAGS": [
          "-L/opt/homebrew/Cellar/snappy/1.1.9/lib"
        ]
      },
      "cflags": [
        # Keep in sync with "OTHER_CFLAGS" above
        "<!@(pkg-config --cflags gmodule-2.0 gnutls libgcrypt glib-2.0)"
      ],
      "libraries": [
        "<(wlibs)/libwireshark.a",
        "<(wlibs)/libcaputils.a",
        "<(wlibs)/libwiretap.a",
        "<(wlibs)/libversion_info.a",
        "<(wlibs)/libwsutil.a",
        "<(wlibs)/libui.a",
        "<!@(pkg-config --libs glib-2.0 gmodule-2.0 gnutls libgcrypt libpcre2-8 zlib libbrotlidec \
          libzstd gpg-error liblz4 libnghttp2 libcares) -lm -lpcap -lsnappy"
      ],
    }, {
      "target_name": "action_after_build",
      "type": "none",
      "dependencies": [ "<(module_name)" ],
      "copies": [
        {
          "files": [ "<(PRODUCT_DIR)/<(module_name).node" ],
          "destination": "<(module_path)"
        }
      ]
    }
  ]
}
