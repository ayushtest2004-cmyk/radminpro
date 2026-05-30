#pragma once
//
// FrameDiff.h - pure tile-based change detection for BGRA frames.
//
// Splitting the screen into fixed tiles and sending only the tiles that changed
// is what keeps the stream "lightweight": a typing/cursor update ships a few KB
// instead of a whole framebuffer. This is deliberately free of any Windows/DXGI
// dependency so it is unit-testable in isolation.
//
#include "common/Util.h"

#include <cstdint>
#include <vector>

namespace rp {

struct RectU {
    uint32_t x = 0, y = 0, w = 0, h = 0;
};

constexpr uint32_t kDefaultTile = 128; // 128*128*4 = 64 KiB, safely < frame cap

// Return the tiles (clamped at right/bottom edges) whose pixels differ between
// `prev` and `cur`. Empty result => frames are identical. If the buffers differ
// in size the caller should treat it as a keyframe (returns empty here).
std::vector<RectU> changedTiles(const Bytes& prev, const Bytes& cur,
                                uint32_t width, uint32_t height, uint32_t stride,
                                uint32_t tile = kDefaultTile);

} // namespace rp
