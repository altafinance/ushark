Ushark is a native module which brings the Wireshark dissection to Nodejs apps.

Internally ushark uses the unofficial Wireshark API and it's linked against its static libraries.

Ushark requires a linux-based distribution in order to be built.

## Code Structure

- The `libushark` folder contains the usark C API and can be used to build native programs (see `libushark/pcap_example.c`).
- The Nodejs module interface is implemented in the `bindings` folder via the [node-addon-api](https://github.com/nodejs/node-addon-api).
- The `pcap_example.js` shows how to use the ushark API from a Nodejs script.

Ushark depends on some Wireshark static libraries. The exposed functions are not part of an official API, so they may change in future Wireshark releases.

This pre-built Wireshark static libraries for linux x64 are provided in the [wireshark-static](https://github.com/altafinance/wireshark-static) submodule.

## Using ushark

The ushark module can be built by sunning `npm install`.

You can run `node pcap_example.js` to see the native module in action.

## Building Wireshark libs

The static libraries of the [wireshark-static](https://github.com/altafinance/wireshark-static) submodule can be built as follows.

First of all, set up the environment as described [here](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterSetup#ChSetupUNIX).

For archlinux, you can find some of the necessary libraries in the [wireshark-git PKGBUILD](https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?h=wireshark-git) (replace `qt5` with `qt6`).
You will also need to install `qt6-5compat`.

Then run:

```
# The wireshark source should be cloned at ../wireshark
cd ..
git clone https://github.com/wireshark/wireshark

cd wireshark
git checkout 85a9e05c

mkdir build
cd build
cmake -DENABLE_STATIC=ON -DENABLE_LUA=OFF -DENABLE_CAP=OFF -DENABLE_KERBEROS=OFF\
  -DENABLE_SBC=OFF -DENABLE_SPANDSP=OFF -DENABLE_BCG729=OFF -DENABLE_ILBC=OFF\
  -DENABLE_LIBXML2=OFF -DENABLE_OPUS=OFF -DENABLE_SINSP=OFF -DENABLE_NETLINK=OFF\
  -DENABLE_PLUGINS=OFF ..

make -j$(nproc) tshark
```

The built Wireshark static libraries will be located in `build/run`.
