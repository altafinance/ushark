#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include "ushark.h"

static void handle_pkt(u_char *user, const struct pcap_pkthdr *hdr, const u_char *buf) {
    ushark_t *sk = (ushark_t*) user;

    const char *json = ushark_dissect(sk, buf, hdr);
    if(json)
        puts(json);
}

int main(int argc, char **argv) {
    static char errbuf[PCAP_ERRBUF_SIZE];
    char *dfilter = NULL;

    if(argc < 2) {
        fprintf(stderr, "usage: ushark pcap_path [display_filter] [keylog_path]\n");
        return -1;
    }

    pcap_t *pd = pcap_open_offline(argv[1], errbuf);
    if(!pd) {
        fprintf(stderr, "pcap open failed: %s\n", errbuf);
        return -1;
    }

    ushark_init();

    if(argc >= 3)
        dfilter = argv[2];

    if(argc >= 4)
        ushark_set_pref("tls.keylog_file", argv[3]);

    ushark_t *sk = ushark_new(pcap_datalink(pd), dfilter);
    pcap_loop(pd, 0, handle_pkt, (u_char*)sk);

    ushark_destroy(sk);
    ushark_cleanup();
    pcap_close(pd);
}
