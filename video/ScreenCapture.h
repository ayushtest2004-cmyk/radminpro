#pragma once
//
// ScreenCapture.h - DXGI Desktop Duplication screen grabber.
//
// Captures the desktop of a chosen monitor into a CPU-readable BGRA buffer.
// PIMPL keeps the D3D11/DXGI headers out of the rest of the build. This module
// knows nothing about networking, auth or audit (separation of concerns).
//
#include "common/Protocol.h" // PixelFormat, Bytes

#include <cstdint>
#include <memory>

namespace rp {

struct Frame {
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t stride = 0; // bytes per row (>= width*4)
    PixelFormat format = PixelFormat::BGRA32;
    Bytes pixels;        // stride * height bytes
};

class ScreenCapture {
public:
    enum class Result {
        Ok,      // `out` populated with a fresh frame
        Timeout, // no screen change within timeout (out untouched)
        Lost,    // duplication invalidated (resolution change, secure desktop) - reinit
        Error,   // unrecoverable
    };

    ScreenCapture();
    ~ScreenCapture();
    ScreenCapture(const ScreenCapture&) = delete;
    ScreenCapture& operator=(const ScreenCapture&) = delete;

    // Initialize duplication for the given monitor index. Returns false on
    // failure (no D3D11, no such output, access denied).
    bool initialize(uint32_t outputIndex = 0);

    Result acquire(Frame& out, uint32_t timeoutMs = 100);

    void shutdown();

    uint32_t width() const;
    uint32_t height() const;

private:
    struct Impl;
    std::unique_ptr<Impl> d_;
};

} // namespace rp
