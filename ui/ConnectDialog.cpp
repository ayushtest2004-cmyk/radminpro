#include "ui/ConnectDialog.h"

#include "ui/WinUtil.h"
#include "ui/resource.h"

#include <windows.h>
#include <commctrl.h>

#include <cstdlib>

namespace rp {

namespace {

struct DlgState {
    std::optional<ClientConfig> result;
};

INT_PTR CALLBACK connectProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* st = reinterpret_cast<DlgState*>(GetWindowLongPtrW(dlg, GWLP_USERDATA));

    switch (msg) {
        case WM_INITDIALOG: {
            SetWindowLongPtrW(dlg, GWLP_USERDATA, lp);
            // Defaults
            winutil::setEditText(dlg, IDC_CONN_PORT, "4899");
            winutil::setChecked(dlg, IDC_CONN_DEFAULT_PORT, true);
            winutil::enableCtrl(dlg, IDC_CONN_PORT, false);
            CheckRadioButton(dlg, IDC_CONN_VIEW, IDC_CONN_FILES, IDC_CONN_VIEW);
            winutil::centerDialog(dlg);
            SetFocus(GetDlgItem(dlg, IDC_CONN_HOST));
            return FALSE; // we set focus ourselves
        }

        case WM_COMMAND: {
            switch (LOWORD(wp)) {
                case IDC_CONN_DEFAULT_PORT: {
                    const bool def = winutil::isChecked(dlg, IDC_CONN_DEFAULT_PORT);
                    if (def) winutil::setEditText(dlg, IDC_CONN_PORT, "4899");
                    winutil::enableCtrl(dlg, IDC_CONN_PORT, !def);
                    return TRUE;
                }
                case IDC_CONN_CA_BROWSE: {
                    std::string f = winutil::browseOpenFile(
                        dlg, L"Select CA bundle (PEM)",
                        L"PEM (*.pem;*.crt)\0*.pem;*.crt\0All files\0*.*\0");
                    if (!f.empty()) winutil::setEditText(dlg, IDC_CONN_CA, f);
                    return TRUE;
                }

                case IDOK: {
                    ClientConfig c;
                    c.host = winutil::getEditText(dlg, IDC_CONN_HOST);
                    const std::string portS = winutil::getEditText(dlg, IDC_CONN_PORT);
                    c.port = portS.empty() ? static_cast<uint16_t>(4899)
                                           : static_cast<uint16_t>(std::atoi(portS.c_str()));
                    c.username = winutil::getEditText(dlg, IDC_CONN_USER);
                    c.password = winutil::getEditText(dlg, IDC_CONN_PASS);
                    c.pinSha256Hex = winutil::getEditText(dlg, IDC_CONN_PIN);
                    c.caPath = winutil::getEditText(dlg, IDC_CONN_CA);
                    if (winutil::isChecked(dlg, IDC_CONN_CONTROL))      c.mode = ConnectionMode::FullControl;
                    else if (winutil::isChecked(dlg, IDC_CONN_FILES))   c.mode = ConnectionMode::FileOnly;
                    else                                                c.mode = ConnectionMode::ViewOnly;

                    // Validation - secure-by-default.
                    if (c.host.empty()) {
                        winutil::messageBoxError(dlg, "Host (IP or DNS) is required.");
                        return TRUE;
                    }
                    if (c.username.empty() || c.password.empty()) {
                        winutil::messageBoxError(dlg, "Username and password are required.");
                        return TRUE;
                    }
                    if (c.pinSha256Hex.empty() && c.caPath.empty()) {
                        winutil::messageBoxError(dlg,
                            "Either a server pin (SHA-256) or a CA file is required.\n"
                            "Connecting without server verification would be insecure.");
                        return TRUE;
                    }

                    if (st) st->result = std::move(c);
                    EndDialog(dlg, IDOK);
                    return TRUE;
                }

                case IDCANCEL:
                    if (st) st->result = std::nullopt;
                    EndDialog(dlg, IDCANCEL);
                    return TRUE;
            }
            break;
        }

        case WM_CLOSE:
            EndDialog(dlg, IDCANCEL);
            return TRUE;
    }
    return FALSE;
}

} // namespace

std::optional<ClientConfig> showConnectDialog() {
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES | ICC_BAR_CLASSES};
    InitCommonControlsEx(&icc);

    DlgState st;
    HINSTANCE hi = GetModuleHandleW(nullptr);
    INT_PTR rc = DialogBoxParamW(hi, MAKEINTRESOURCEW(IDD_CONNECT), nullptr,
                                 connectProc, reinterpret_cast<LPARAM>(&st));
    if (rc != IDOK) return std::nullopt;
    return st.result;
}

} // namespace rp
