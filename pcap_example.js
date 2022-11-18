const pcap = require('pcap');
const ushark = require('./index');

const pcap_path = process.argv[2];
const dfilter = (process.argv.length) >= 4 ? process.argv[3] : null;
const keylog_path = (process.argv.length) >= 5 ? process.argv[4] : null;

if(!pcap_path) {
  console.error(`Usage: pcap_example pcap_path [display_filter] [keylog_path]`);
  process.exit(1);
}

if(keylog_path)
  ushark.setPref("tls.keylog_file", keylog_path);

const pcap_session = pcap.createOfflineSession(pcap_path);
const link_type = ushark[pcap_session.link_type] || ushark.LINKTYPE_RAW;
const dissector = new ushark.Dissector(link_type, dfilter);

pcap_session.on('packet', (pkt) => {
  dissector.dissect(pkt.buf, pkt.header);
});

pcap_session.on('complete', () => {
  console.log(dissector.json());
});
