.PHONY: clean

build/Release/ushark.node: libushark/libushark.a binding.gyp $(shell find bindings -type f)
	node-gyp configure
	node-gyp rebuild --verbose

libushark/libushark.a: $(shell find libushark -name '*.c' -o -name '*.h')
	$(MAKE) -C libushark CC=clang libushark.a

clean:
	$(MAKE) -C libushark clean
	rm -rf build
