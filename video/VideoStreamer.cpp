#include "video/VideoStreamer.h"

#include "common/FrameDiff.h"
#include "common/Util.h"

#include <algorithm>
#include <cstring>

namespace rp {

VideoStreamer::Step VideoStreamer::streamOnce(uint32_t timeoutMs) {
    Frame frame;
    switch (cap_.acquire(frame, timeoutMs)) {
        case ScreenCapture::Result::Timeout:
            return Step::Skipped;
        case ScreenCapture::Result::Lost:
            sentKeyframe_ = false; // re-sync with a fresh keyframe once restored
            return Step::Lost;
        case ScreenCapture::Result::Error:
            return Step::Error;
        case ScreenCapture::Result::Ok:
            break;
    }

    const bool geomChanged = frame.width != prevW_ || frame.height != prevH_ ||
                             frame.stride != prevStride_ ||
                             prevFrame_.size() != frame.pixels.size();
    if (!sentKeyframe_ || geomChanged) return sendKeyframe(frame);
    return sendDelta(frame);
}

VideoStreamer::Step VideoStreamer::sendKeyframe(const Frame& frame) {
    const uint32_t seq = ++seq_;

    FrameInfoMsg info;
    info.sequence = seq;
    info.width = static_cast<uint16_t>(frame.width);
    info.height = static_cast<uint16_t>(frame.height);
    info.stride = frame.stride;
    info.format = frame.format;
    info.keyframe = true;
    if (!send_(Op::FrameInfo, info.encode())) return Step::Error;

    const size_t total = frame.pixels.size();
    for (size_t off = 0; off < total; off += kVideoChunkSize) {
        const size_t n = std::min<size_t>(kVideoChunkSize, total - off);
        FrameDataMsg chunk;
        chunk.sequence = seq;
        chunk.offset = static_cast<uint32_t>(off);
        chunk.data.assign(frame.pixels.begin() + off, frame.pixels.begin() + off + n);
        if (!send_(Op::FrameData, chunk.encode())) return Step::Error;
    }

    Bytes endPayload;
    putU32(endPayload, seq);
    if (!send_(Op::FrameEnd, endPayload)) return Step::Error;

    prevFrame_ = frame.pixels;
    prevW_ = frame.width;
    prevH_ = frame.height;
    prevStride_ = frame.stride;
    sentKeyframe_ = true;
    return Step::Sent;
}

VideoStreamer::Step VideoStreamer::sendDelta(const Frame& frame) {
    std::vector<RectU> rects =
        changedTiles(prevFrame_, frame.pixels, frame.width, frame.height, frame.stride);
    if (rects.empty()) return Step::Skipped;

    const uint32_t seq = ++seq_;
    const uint32_t stride = frame.stride;

    for (const RectU& rc : rects) {
        const size_t rowBytes = static_cast<size_t>(rc.w) * 4;
        FrameRectMsg m;
        m.sequence = seq;
        m.x = static_cast<uint16_t>(rc.x);
        m.y = static_cast<uint16_t>(rc.y);
        m.w = static_cast<uint16_t>(rc.w);
        m.h = static_cast<uint16_t>(rc.h);
        m.pixels.resize(rowBytes * rc.h);

        for (uint32_t r = 0; r < rc.h; ++r) {
            const size_t srcOff =
                static_cast<size_t>(rc.y + r) * stride + static_cast<size_t>(rc.x) * 4;
            std::memcpy(m.pixels.data() + static_cast<size_t>(r) * rowBytes,
                        frame.pixels.data() + srcOff, rowBytes);
            // Mirror into prevFrame_ so the next diff is against what the client has.
            std::memcpy(prevFrame_.data() + srcOff, frame.pixels.data() + srcOff, rowBytes);
        }
        if (!send_(Op::FrameRect, m.encode())) return Step::Error;
    }

    Bytes endPayload;
    putU32(endPayload, seq);
    if (!send_(Op::FrameEnd, endPayload)) return Step::Error;
    return Step::Sent;
}

} // namespace rp
