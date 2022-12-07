.PHONY: clean package

build/Release/ushark.node: libushark/ushark.c libushark/ushark.h binding.gyp $(shell find bindings -type f)
	node-gyp configure
	node-gyp rebuild --verbose

package:
	npm install --ignore-scripts
	./node_modules/.bin/node-pre-gyp configure
	./node_modules/.bin/node-pre-gyp build
	./node_modules/.bin/node-pre-gyp package

clean:
	$(MAKE) -C libushark clean
	rm -rf build build-tmp-napi-v* lib
