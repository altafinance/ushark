#include "dissector.hpp"

extern "C" {
#include <pcap/pcap.h>
#include <wsutil/wslog.h>
}

Dissector::Dissector(const Napi::CallbackInfo& info) :
        Napi::ObjectWrap<Dissector>(info) {
    auto value = info[0].As<Napi::Number>();
    std::string dfilter;

    if((info.Length() > 1) && info[1].IsString())
        dfilter = info[1].As<Napi::String>().Utf8Value();

    linkLayerType = value.Uint32Value();
    sk = ushark_new(linkLayerType, dfilter.c_str());
}

Dissector::~Dissector() {
    ushark_destroy(sk);
}

Napi::Value Dissector::dissect(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
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

    auto json = ushark_dissect(sk, pkt.Data(), &pkthdr);
    if(json)
        return Napi::String::New(env, json);
    return env.Null();
}

Napi::Object Dissector::Init(Napi::Env env, Napi::Object exports) {
    // Define the class API
    Napi::Function func = DefineClass(env, "Dissector", {
            // Properties
            // https://github.com/nodejs/node-addon-api/blob/main/doc/class_property_descriptor.md
            InstanceAccessor<&Dissector::getLinkLayerType>("link_type"),
            InstanceMethod("dissect", &Dissector::dissect)
    });

    // https://github.com/nodejs/node-addon-api/blob/main/doc/object_wrap.md
    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);
    env.SetInstanceData(constructor);
    exports.Set("Dissector", func);

    return exports;
}
