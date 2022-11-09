#ifndef _USHARK_H_
#define _USHARK_H_

typedef struct ushark ushark_t;
struct pcap_pkthdr;

void ushark_init();
void ushark_cleanup();

ushark_t* ushark_new(int pcap_encap);
void ushark_destroy(ushark_t *sk);
void ushark_set_pref(const char *name, const char *val);
void ushark_dissect(ushark_t *sk, const unsigned char *buf, const struct pcap_pkthdr *hdr);
const char* ushark_get_json(ushark_t *sk);

#endif
