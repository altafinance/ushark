Ushark is a native module which brings the Wireshark dissection to Nodejs apps.

Internally ushark uses the unofficial Wireshark API and it's linked against its static libraries.

## Using ushark

Ushark currently supports:

- linux x64 - built for Ubuntu 22.04
- darwin-arm64 - built for macOS 12

The ushark module can be installed as a normal node module. `node-pre-gyp-github` installs the pre-built binaries for the specific OS and architecture.
To build and run on unsupported platforms, see "Building the Wireshark libs" and "Building the binary module" below.

You can run `node pcap_example.js` to see the native module in action.

## Code Structure

- The `libushark` folder contains the usark C API and can be used to build native programs (see `libushark/pcap_example.c`).
- The Nodejs module interface is implemented in the `bindings` folder via the [node-addon-api](https://github.com/nodejs/node-addon-api).
- The `pcap_example.js` shows how to use the ushark API from a Nodejs script.

Ushark depends on some Wireshark static libraries. The exposed functions are not part of an official API, so they may change in future Wireshark releases.

## Building the Wireshark libs

First of all, set up the environment as described [here](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterSetup#ChSetupUNIX).

On Ubuntu 22.04, you will need at least the following packages:

```
apt install build-essential cmake flex libglib2.0-dev libgnutls28-dev libgcrypt20-dev\
  libpcre2-dev zlib1g-dev libbrotli-dev libzstd-dev libgpg-error-dev liblz4-dev\
  libnghttp2-dev libc-ares-dev libsnappy-dev libpcap-dev
```

On macOS, you can run `tools/macos-setup.sh` to install all the dependencies.

To build the static libraries, run:

```
# The wireshark source should be cloned at ../wireshark
cd ..
git clone https://github.com/wireshark/wireshark

cd wireshark
git checkout 85a9e05c

mkdir build
cd build
cmake -DENABLE_STATIC=ON -DBUILD_wireshark=OFF -DENABLE_LUA=OFF -DENABLE_CAP=OFF -DENABLE_KERBEROS=OFF\
  -DENABLE_SBC=OFF -DENABLE_SPANDSP=OFF -DENABLE_BCG729=OFF -DENABLE_ILBC=OFF\
  -DENABLE_LIBXML2=OFF -DENABLE_OPUS=OFF -DENABLE_SINSP=OFF -DENABLE_NETLINK=OFF\
  -DENABLE_PLUGINS=OFF -DENABLE_AIRPCAP=OFF -DENABLE_SMI=OFF ..

make -j$(nproc) tshark
```

The built Wireshark static libraries will be located in `build/run`.

## Building the Binary Module

After building the wireshark static libraries, the binary node module can be built with:

```
npm install --build-from-source
```

(optional) To build the `tar.gz` containing the binary module for the release, run:

```
make package
```
