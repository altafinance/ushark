#ifndef USHARK_DISSECTOR_H
#define USHARK_DISSECTOR_H

#include <napi.h>

extern "C" {
#include "libushark/ushark.h"
}

class Dissector : public Napi::ObjectWrap<Dissector> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    Dissector(const Napi::CallbackInfo &info);
    ~Dissector();
    void dissect(const Napi::CallbackInfo &info);
    Napi::Value dumpJson(const Napi::CallbackInfo &info);

private:
    struct ushark *sk;
    int linkLayerType;

    inline Napi::Value getLinkLayerType(const Napi::CallbackInfo &info) {
      return Napi::Number::New(info.Env(), this->linkLayerType);
    }
};

#endif
