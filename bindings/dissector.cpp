#include "dissector.hpp"

extern "C" {
#include <pcap/pcap.h>
#include <wsutil/wslog.h>
}

Dissector::Dissector(const Napi::CallbackInfo& info) :
        Napi::ObjectWrap<Dissector>(info) {
    auto value = info[0].As<Napi::Number>();

    linkLayerType = value.Uint32Value();
    sk = ushark_new(linkLayerType);
}

Dissector::~Dissector() {
    ushark_destroy(sk);
}

void Dissector::dissect(const Napi::CallbackInfo &info) {
    auto pkt = info[0].As<const Napi::Buffer<uint8_t>>();
    auto hdr = info[1].As<const Napi::Buffer<uint8_t>>();

    if(hdr.Length() != 16)
        ws_error("Invalid PCAP header buffer length: %zu", hdr.Length());

    // Unpack the PCAP header, see PcapSession::PacketReady
    struct pcap_pkthdr pkthdr = {};
    auto hbuf = hdr.Data();
    memcpy(&pkthdr.ts.tv_sec,   hbuf + 0, 4);
    memcpy(&pkthdr.ts.tv_usec,  hbuf + 4, 4);
    memcpy(&pkthdr.caplen,      hbuf + 8, 4);
    memcpy(&pkthdr.len,         hbuf + 12, 4);

    ushark_dissect(sk, pkt.Data(), &pkthdr);
}

Napi::Value Dissector::dumpJson(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    return Napi::String::New(env, ushark_get_json(sk));
}

Napi::Object Dissector::Init(Napi::Env env, Napi::Object exports) {
    // Define the class API
    Napi::Function func = DefineClass(env, "Dissector", {
            // Properties
            // https://github.com/nodejs/node-addon-api/blob/main/doc/class_property_descriptor.md
            InstanceAccessor<&Dissector::getLinkLayerType>("link_type"),
            InstanceMethod("dissect", &Dissector::dissect),
            InstanceMethod("json", &Dissector::dumpJson)
    });

    // https://github.com/nodejs/node-addon-api/blob/main/doc/object_wrap.md
    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);
    env.SetInstanceData(constructor);
    exports.Set("Dissector", func);

    return exports;
}
