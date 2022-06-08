# NOTE: Every line in a recipe must begin with a tab character.
BUILD_DIR ?= target

PREFIX ?=          /usr/local
LUA_INCLUDE_DIR ?= $(PREFIX)/include
LUA_LIB_DIR ?=     $(PREFIX)/lib/lua/$(LUA_VERSION)
INSTALL ?= install

.PHONY: all clean test install

all: ;

install: all
	$(INSTALL) -d $(DESTDIR)/$(LUA_LIB_DIR)/api-gateway/crypto/
	$(INSTALL) src/lua/api-gateway/crypto/*.lua $(DESTDIR)/$(LUA_LIB_DIR)/api-gateway/crypto/

test:
	echo "updating git submodules ..."
	if [ ! -d "test/resources/test-nginx/lib" ]; then	git submodule update --init --recursive; fi
	echo "running tests ..."
#	cp -r test/resources/api-gateway $(BUILD_DIR)
	mkdir  -p $(BUILD_DIR)/
	PATH=/usr/local/sbin:$$PATH TEST_NGINX_SERVROOT=`pwd`/$(BUILD_DIR)/servroot TEST_NGINX_PORT=1989 prove -I ./test/resources/test-nginx/lib -r ./test/perl

package:
	git archive --format=tar --prefix=api-gateway-crypto-1.0/ -o api-gateway-crypto-1.0.tar.gz -v HEAD

clean: all
	rm -rf $(BUILD_DIR)/servroot