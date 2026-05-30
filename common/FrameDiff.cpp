#include "common/FrameDiff.h"

#include <algorithm>
#include <cstring>

namespace rp {

std::vector<RectU> changedTiles(const Bytes& prev, const Bytes& cur, uint32_t width,
                                uint32_t height, uint32_t stride, uint32_t tile) {
    std::vector<RectU> out;
    if (prev.size() != cur.size()) return out; // size change => keyframe (caller)
    if (tile == 0) tile = kDefaultTile;

    for (uint32_t ty = 0; ty < height; ty += tile) {
        const uint32_t th = std::min(tile, height - ty);
        for (uint32_t tx = 0; tx < width; tx += tile) {
            const uint32_t tw = std::min(tile, width - tx);
            const size_t rowBytes = static_cast<size_t>(tw) * 4;

            bool diff = false;
            for (uint32_t r = 0; r < th; ++r) {
                const size_t off = static_cast<size_t>(ty + r) * stride +
                                   static_cast<size_t>(tx) * 4;
                if (off + rowBytes > cur.size()) { diff = true; break; }
                if (std::memcmp(cur.data() + off, prev.data() + off, rowBytes) != 0) {
                    diff = true;
                    break;
                }
            }
            if (diff) out.push_back(RectU{tx, ty, tw, th});
        }
    }
    return out;
}

} // namespace rp
