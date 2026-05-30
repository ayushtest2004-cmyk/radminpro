#pragma once
//
// VideoStreamer.h - turns captured frames into protocol messages.
//
// It pulls frames from a ScreenCapture and emits FrameInfo + chunked FrameData
// + FrameEnd through a caller-supplied send function. It is intentionally
// transport-agnostic and security-agnostic: the server session loop supplies a
// `SendFn` that enforces rights/mode and writes to the TLS socket. This keeps
// the Video Streamer cleanly separated from the Security Manager.
//
#include "common/Protocol.h"
#include "video/ScreenCapture.h"

#include <functional>

namespace rp {

// Max pixel bytes per FrameData chunk (well under kMaxMessageSize).
constexpr uint32_t kVideoChunkSize = 256u * 1024;

class VideoStreamer {
public:
    // Returns false to abort streaming (e.g. socket closed).
    using SendFn = std::function<bool(Op op, const Bytes& payload)>;

    VideoStreamer(ScreenCapture& capture, SendFn send)
        : cap_(capture), send_(std::move(send)) {}

    enum class Step {
        Sent,    // a fresh frame was transmitted
        Skipped, // no change / timeout - nothing sent
        Lost,    // capture invalidated; caller should reinitialize capture
        Error,   // transport or capture error; end session
    };

    // Capture (up to timeoutMs) and, if the screen changed, stream one frame:
    // a full keyframe (FrameInfo + FrameData chunks) the first time / after a
    // capture reset / on geometry change, otherwise only changed tiles as
    // FrameRect deltas. Always terminated by FrameEnd.
    Step streamOnce(uint32_t timeoutMs = 100);

    uint32_t lastSequence() const { return seq_; }

private:
    Step sendKeyframe(const Frame& frame);
    Step sendDelta(const Frame& frame);

    ScreenCapture& cap_;
    SendFn send_;
    uint32_t seq_ = 0;

    Bytes prevFrame_;          // last frame we transmitted (mirrors the client)
    uint32_t prevW_ = 0, prevH_ = 0, prevStride_ = 0;
    bool sentKeyframe_ = false;
};

} // namespace rp
