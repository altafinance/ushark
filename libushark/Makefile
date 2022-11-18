.PHONY: clean

WIRESHARK := ../wireshark-static
WLIBS := $(WIRESHARK)/libs

CFLAGS := -g -O0 -I$(WIRESHARK) -I$(WIRESHARK)/include -I$(WIRESHARK)/build \
	`pkgconf --cflags gmodule-2.0 gnutls libgcrypt`

%.o :
	$(CC) $(CFLAGS) -Wall -c -o $@ $^

pcap_example: pcap_example.o libushark.a $(WLIBS)/libwireshark.a $(WLIBS)/libcaputils.a \
		$(WLIBS)/libwiretap.a $(WLIBS)/libversion_info.a $(WLIBS)/libwsutil.a \
		$(WLIBS)/libui.a
	$(CC) -o $@ $(CFLAGS) $^ \
		`pkgconf --libs glib-2.0 gmodule-2.0 gnutls libgcrypt libpcre2-8 zlib libbrotlidec \
		libzstd gpg-error liblz4 libnghttp2 libcares snappy libpcap` -lm

pcap_example.o: pcap_example.c

libushark.a: frame_tvbuff.o ushark.o
	ar rcs $@ $^

frame_tvbuff.o: $(WIRESHARK)/frame_tvbuff.c

ushark.o: ushark.c

clean:
	rm -f *.o libushark.a pcap_example
