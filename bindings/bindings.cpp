#include "dissector.hpp"

static void init(const Napi::CallbackInfo &info) {
    ushark_init();
}

static void setPref(const Napi::CallbackInfo &info) {
    auto name = info[0].As<Napi::String>().Utf8Value();
    auto val = info[1].As<Napi::String>().Utf8Value();

    ushark_set_pref(name.c_str(), val.c_str());
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    Dissector::Init(env, exports);
    exports.Set(Napi::String::New(env, "init"), Napi::Function::New(env, init));
    exports.Set(Napi::String::New(env, "setPref"), Napi::Function::New(env, setPref));

    return exports;
}

NODE_API_MODULE(ushark, Init)
