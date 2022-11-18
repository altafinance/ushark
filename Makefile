.PHONY: clean

build/Release/ushark.node: libushark/ushark.c libushark/ushark.h binding.gyp $(shell find bindings -type f)
	node-gyp configure
	node-gyp rebuild --verbose

clean:
	$(MAKE) -C libushark clean
	rm -rf build
