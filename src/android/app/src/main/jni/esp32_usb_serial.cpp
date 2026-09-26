// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

// JNI half of the ESP32 serial link: installs a SerialPort factory into the core whose port calls
// the Kotlin object org.citra.citra_emu.utils.Esp32UsbLink.

#include <algorithm>
#include <memory>
#include <jni.h>

#include "common/logging/log.h"
#include "core/hle/service/nwm/uds_real/esp32_serial.h"
#include "id_cache.h"

namespace {

using Service::NWM::UdsReal::Esp32::SerialPort;

jclass link_class{};
jmethodID open_method{};
jmethodID close_method{};
jmethodID read_method{};
jmethodID write_method{};

class UsbSerialPort final : public SerialPort {
public:
    ~UsbSerialPort() override {
        JNIEnv* env = IDCache::GetEnvForThread();
        env->CallStaticVoidMethod(link_class, close_method);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }

    int Read(std::span<u8> buffer, int timeout_ms) override {
        JNIEnv* env = IDCache::GetEnvForThread();
        const jsize capacity = static_cast<jsize>(std::min<std::size_t>(buffer.size(), 4096));
        jbyteArray array = env->NewByteArray(capacity);
        const jint count =
            env->CallStaticIntMethod(link_class, read_method, array, static_cast<jint>(timeout_ms));
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            env->DeleteLocalRef(array);
            return -1;
        }
        if (count > 0) {
            env->GetByteArrayRegion(array, 0, count, reinterpret_cast<jbyte*>(buffer.data()));
        }
        env->DeleteLocalRef(array);
        return count;
    }

    bool Write(std::span<const u8> data) override {
        JNIEnv* env = IDCache::GetEnvForThread();
        const jsize length = static_cast<jsize>(data.size());
        jbyteArray array = env->NewByteArray(length);
        env->SetByteArrayRegion(array, 0, length, reinterpret_cast<const jbyte*>(data.data()));
        const jboolean ok = env->CallStaticBooleanMethod(link_class, write_method, array, length);
        const bool failed = env->ExceptionCheck();
        if (failed) {
            env->ExceptionClear();
        }
        env->DeleteLocalRef(array);
        return ok && !failed;
    }
};

std::unique_ptr<SerialPort> OpenUsbSerialPort() {
    JNIEnv* env = IDCache::GetEnvForThread();
    const jboolean opened = env->CallStaticBooleanMethod(link_class, open_method);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }
    return opened ? std::make_unique<UsbSerialPort>() : nullptr;
}

} // namespace

extern "C" JNIEXPORT void JNICALL
Java_org_citra_citra_1emu_utils_Esp32UsbLink_nativeInstall(JNIEnv* env, jclass clazz) {
    link_class = static_cast<jclass>(env->NewGlobalRef(clazz));
    open_method = env->GetStaticMethodID(clazz, "open", "()Z");
    close_method = env->GetStaticMethodID(clazz, "close", "()V");
    read_method = env->GetStaticMethodID(clazz, "read", "([BI)I");
    write_method = env->GetStaticMethodID(clazz, "write", "([BI)Z");
    if (!open_method || !close_method || !read_method || !write_method) {
        LOG_ERROR(Service_NWM, "ESP32 USB link: Esp32UsbLink methods not found");
        return;
    }
    Service::NWM::UdsReal::Esp32::SetSerialFactory(OpenUsbSerialPort);
}
