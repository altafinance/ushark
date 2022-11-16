const bindings = require("./build/Release/ushark.node");

// https://www.tcpdump.org/linktypes.html
exports.LINKTYPE_NULL             = 0;
exports.LINKTYPE_ETHERNET         = 1;
exports.LINKTYPE_RAW              = 101;
exports.LINKTYPE_LINUX_SLL        = 113;
exports.LINKTYPE_LINUX_SLL2       = 276;
exports.LINKTYPE_IEEE802_11_RADIO = 127;

exports.Dissector = bindings.Dissector;
exports.setPref = bindings.setPref;

bindings.init();
