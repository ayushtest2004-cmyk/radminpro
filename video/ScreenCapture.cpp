#include "video/ScreenCapture.h"

#include "common/Logger.h"

#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include <cstring>

using Microsoft::WRL::ComPtr;

namespace rp {

struct ScreenCapture::Impl {
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IDXGIOutputDuplication> dup;
    ComPtr<ID3D11Texture2D> staging;
    uint32_t stagingW = 0, stagingH = 0;
    uint32_t width = 0, height = 0;

    void releaseCom() {
        staging.Reset();
        dup.Reset();
        context.Reset();
        device.Reset();
        stagingW = stagingH = width = height = 0;
    }
};

ScreenCapture::ScreenCapture() : d_(std::make_unique<Impl>()) {}
ScreenCapture::~ScreenCapture() { shutdown(); }

void ScreenCapture::shutdown() {
    if (d_) d_->releaseCom();
}

uint32_t ScreenCapture::width() const { return d_->width; }
uint32_t ScreenCapture::height() const { return d_->height; }

bool ScreenCapture::initialize(uint32_t outputIndex) {
    d_->releaseCom();

    const D3D_FEATURE_LEVEL levels[] = {
        D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0,
    };
    D3D_FEATURE_LEVEL got{};
    HRESULT hr = D3D11CreateDevice(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, ARRAYSIZE(levels),
        D3D11_SDK_VERSION, d_->device.GetAddressOf(), &got, d_->context.GetAddressOf());
    if (FAILED(hr)) {
        RP_LOG_ERROR("D3D11CreateDevice failed (hr=" + std::to_string(hr) + ")");
        return false;
    }

    ComPtr<IDXGIDevice> dxgiDev;
    if (FAILED(d_->device.As(&dxgiDev))) return false;
    ComPtr<IDXGIAdapter> adapter;
    if (FAILED(dxgiDev->GetAdapter(adapter.GetAddressOf()))) return false;

    ComPtr<IDXGIOutput> output;
    hr = adapter->EnumOutputs(outputIndex, output.GetAddressOf());
    if (FAILED(hr)) {
        RP_LOG_ERROR("no monitor at output index " + std::to_string(outputIndex));
        return false;
    }
    DXGI_OUTPUT_DESC odesc{};
    output->GetDesc(&odesc);
    d_->width = static_cast<uint32_t>(odesc.DesktopCoordinates.right - odesc.DesktopCoordinates.left);
    d_->height = static_cast<uint32_t>(odesc.DesktopCoordinates.bottom - odesc.DesktopCoordinates.top);

    ComPtr<IDXGIOutput1> output1;
    if (FAILED(output.As(&output1))) return false;

    hr = output1->DuplicateOutput(d_->device.Get(), d_->dup.GetAddressOf());
    if (FAILED(hr)) {
        // E_ACCESSDENIED commonly means another duplication is already active.
        RP_LOG_ERROR("DuplicateOutput failed (hr=" + std::to_string(hr) + ")");
        return false;
    }
    RP_LOG_INFO("screen capture initialized: " + std::to_string(d_->width) + "x" +
                std::to_string(d_->height));
    return true;
}

ScreenCapture::Result ScreenCapture::acquire(Frame& out, uint32_t timeoutMs) {
    if (!d_->dup) return Result::Lost;

    DXGI_OUTDUPL_FRAME_INFO info{};
    ComPtr<IDXGIResource> res;
    HRESULT hr = d_->dup->AcquireNextFrame(timeoutMs, &info, res.GetAddressOf());
    if (hr == DXGI_ERROR_WAIT_TIMEOUT) return Result::Timeout;
    if (hr == DXGI_ERROR_ACCESS_LOST) return Result::Lost;
    if (FAILED(hr)) return Result::Error;

    // LastPresentTime == 0 means only the mouse moved, not the desktop image.
    if (info.LastPresentTime.QuadPart == 0) {
        d_->dup->ReleaseFrame();
        return Result::Timeout;
    }

    ComPtr<ID3D11Texture2D> tex;
    if (FAILED(res.As(&tex))) {
        d_->dup->ReleaseFrame();
        return Result::Error;
    }
    D3D11_TEXTURE2D_DESC desc{};
    tex->GetDesc(&desc);

    // (Re)create CPU-readable staging texture if geometry changed.
    if (!d_->staging || d_->stagingW != desc.Width || d_->stagingH != desc.Height) {
        d_->staging.Reset();
        D3D11_TEXTURE2D_DESC sd = desc;
        sd.Usage = D3D11_USAGE_STAGING;
        sd.BindFlags = 0;
        sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        sd.MiscFlags = 0;
        if (FAILED(d_->device->CreateTexture2D(&sd, nullptr, d_->staging.GetAddressOf()))) {
            d_->dup->ReleaseFrame();
            return Result::Error;
        }
        d_->stagingW = desc.Width;
        d_->stagingH = desc.Height;
    }

    d_->context->CopyResource(d_->staging.Get(), tex.Get());

    D3D11_MAPPED_SUBRESOURCE map{};
    hr = d_->context->Map(d_->staging.Get(), 0, D3D11_MAP_READ, 0, &map);
    if (FAILED(hr)) {
        d_->dup->ReleaseFrame();
        return Result::Error;
    }

    out.width = desc.Width;
    out.height = desc.Height;
    out.stride = desc.Width * 4; // tightly packed BGRA in our buffer
    out.format = PixelFormat::BGRA32;
    out.pixels.resize(static_cast<size_t>(out.stride) * out.height);

    const auto* src = static_cast<const uint8_t*>(map.pData);
    for (uint32_t y = 0; y < out.height; ++y) {
        std::memcpy(out.pixels.data() + static_cast<size_t>(y) * out.stride,
                    src + static_cast<size_t>(y) * map.RowPitch, out.stride);
    }

    d_->context->Unmap(d_->staging.Get(), 0);
    d_->dup->ReleaseFrame();
    return Result::Ok;
}

} // namespace rp
