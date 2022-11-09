#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include "ushark.h"

static void handle_pkt(u_char *user, const struct pcap_pkthdr *hdr, const u_char *buf) {
    ushark_t *sk = (ushark_t*) user;

    ushark_dissect(sk, buf, hdr);
}

int main(int argc, char **argv) {
    static char errbuf[PCAP_ERRBUF_SIZE];

    if(argc < 2) {
        fprintf(stderr, "usage: ushark pcap_path keylog_path\n");
        return -1;
    }

    pcap_t *pd = pcap_open_offline(argv[1], errbuf);
    if(!pd) {
        fprintf(stderr, "pcap open failed: %s\n", errbuf);
        return -1;
    }

    ushark_init();
    if(argc == 3)
        ushark_set_pref("tls.keylog_file", argv[2]);

    ushark_t *sk = ushark_new(pcap_datalink(pd));
    pcap_loop(pd, 0, handle_pkt, (u_char*)sk);

    // print JSON
    puts(ushark_get_json(sk));

    ushark_destroy(sk);
    ushark_cleanup();
    pcap_close(pd);
}
