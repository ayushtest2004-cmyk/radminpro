#include "ui/OptionsDialog.h"

#include "ui/WinUtil.h"
#include "ui/resource.h"

#include <windows.h>
#include <commctrl.h>

#include <cstdlib>
#include <string>

namespace rp {

namespace {

// Sub-dialogs receive this to flush their fields back into the ServerConfig.
constexpr UINT WM_OPT_SAVE = WM_APP + 1;

struct Parent {
    ServerConfig* cfg = nullptr;
    HWND pages[3] = {nullptr, nullptr, nullptr}; // General, Filter, Logging
};

// =========================================================================
// General page
// =========================================================================
INT_PTR CALLBACK generalProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* cfg = reinterpret_cast<ServerConfig*>(GetWindowLongPtrW(dlg, GWLP_USERDATA));
    switch (msg) {
        case WM_INITDIALOG: {
            SetWindowLongPtrW(dlg, GWLP_USERDATA, lp);
            cfg = reinterpret_cast<ServerConfig*>(lp);
            winutil::setEditText(dlg, IDC_OPT_BIND, cfg->bindAddr);
            winutil::setEditText(dlg, IDC_OPT_PORT, std::to_string(cfg->port));
            winutil::setChecked  (dlg, IDC_OPT_USE_DEFAULT, cfg->port == 4899);
            winutil::setEditText(dlg, IDC_OPT_MAX_SESS, std::to_string(cfg->maxSessions));
            winutil::setEditText(dlg, IDC_OPT_MONITOR,  std::to_string(cfg->monitor));
            winutil::setEditText(dlg, IDC_OPT_CERT, cfg->tlsCert);
            winutil::setEditText(dlg, IDC_OPT_KEY,  cfg->tlsKey);
            return TRUE;
        }
        case WM_COMMAND: {
            switch (LOWORD(wp)) {
                case IDC_OPT_USE_DEFAULT:
                    if (winutil::isChecked(dlg, IDC_OPT_USE_DEFAULT))
                        winutil::setEditText(dlg, IDC_OPT_PORT, "4899");
                    return TRUE;
                case IDC_OPT_CERT_BROWSE: {
                    auto f = winutil::browseOpenFile(dlg, L"Server certificate",
                        L"Cert (*.crt;*.pem)\0*.crt;*.pem\0All files\0*.*\0");
                    if (!f.empty()) winutil::setEditText(dlg, IDC_OPT_CERT, f);
                    return TRUE;
                }
                case IDC_OPT_KEY_BROWSE: {
                    auto f = winutil::browseOpenFile(dlg, L"Server private key",
                        L"Key (*.key;*.pem)\0*.key;*.pem\0All files\0*.*\0");
                    if (!f.empty()) winutil::setEditText(dlg, IDC_OPT_KEY, f);
                    return TRUE;
                }
            }
            break;
        }
        case WM_OPT_SAVE: {
            if (!cfg) return TRUE;
            cfg->bindAddr    = winutil::getEditText(dlg, IDC_OPT_BIND);
            cfg->port        = static_cast<uint16_t>(std::atoi(winutil::getEditText(dlg, IDC_OPT_PORT).c_str()));
            cfg->maxSessions = static_cast<uint32_t>(std::atoi(winutil::getEditText(dlg, IDC_OPT_MAX_SESS).c_str()));
            cfg->monitor     = static_cast<uint32_t>(std::atoi(winutil::getEditText(dlg, IDC_OPT_MONITOR).c_str()));
            cfg->tlsCert     = winutil::getEditText(dlg, IDC_OPT_CERT);
            cfg->tlsKey      = winutil::getEditText(dlg, IDC_OPT_KEY);
            return TRUE;
        }
    }
    return FALSE;
}

// =========================================================================
// IP Filter page
// =========================================================================
INT_PTR CALLBACK filterProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* cfg = reinterpret_cast<ServerConfig*>(GetWindowLongPtrW(dlg, GWLP_USERDATA));
    switch (msg) {
        case WM_INITDIALOG: {
            SetWindowLongPtrW(dlg, GWLP_USERDATA, lp);
            cfg = reinterpret_cast<ServerConfig*>(lp);
            HWND lst = GetDlgItem(dlg, IDC_OPT_CIDR_LIST);
            std::string cur;
            auto flush = [&]() {
                while (!cur.empty() && (cur.back()  == ' ' || cur.back()  == '\t')) cur.pop_back();
                while (!cur.empty() && (cur.front() == ' ' || cur.front() == '\t')) cur.erase(0, 1);
                if (!cur.empty()) {
                    SendMessageW(lst, LB_ADDSTRING, 0,
                                 reinterpret_cast<LPARAM>(winutil::widen(cur).c_str()));
                }
                cur.clear();
            };
            for (char c : cfg->allowSubnets) {
                if (c == ',' || c == ' ' || c == '\t' || c == '\n' || c == '\r') flush();
                else cur.push_back(c);
            }
            flush();
            return TRUE;
        }
        case WM_COMMAND: {
            switch (LOWORD(wp)) {
                case IDC_OPT_CIDR_ADD: {
                    std::string v = winutil::getEditText(dlg, IDC_OPT_CIDR_EDIT);
                    if (v.empty()) return TRUE;
                    SendMessageW(GetDlgItem(dlg, IDC_OPT_CIDR_LIST), LB_ADDSTRING, 0,
                                 reinterpret_cast<LPARAM>(winutil::widen(v).c_str()));
                    winutil::setEditText(dlg, IDC_OPT_CIDR_EDIT, "");
                    return TRUE;
                }
                case IDC_OPT_CIDR_REMOVE: {
                    HWND lst = GetDlgItem(dlg, IDC_OPT_CIDR_LIST);
                    int sel = static_cast<int>(SendMessageW(lst, LB_GETCURSEL, 0, 0));
                    if (sel != LB_ERR) SendMessageW(lst, LB_DELETESTRING, sel, 0);
                    return TRUE;
                }
            }
            break;
        }
        case WM_OPT_SAVE: {
            if (!cfg) return TRUE;
            HWND lst = GetDlgItem(dlg, IDC_OPT_CIDR_LIST);
            int n = static_cast<int>(SendMessageW(lst, LB_GETCOUNT, 0, 0));
            std::string acc;
            for (int i = 0; i < n; ++i) {
                int len = static_cast<int>(SendMessageW(lst, LB_GETTEXTLEN, i, 0));
                std::wstring w(static_cast<size_t>(len) + 1, L'\0');
                SendMessageW(lst, LB_GETTEXT, i, reinterpret_cast<LPARAM>(w.data()));
                w.resize(len);
                if (!acc.empty()) acc += ",";
                acc += winutil::narrow(w);
            }
            cfg->allowSubnets = acc;
            return TRUE;
        }
    }
    return FALSE;
}

// =========================================================================
// Logging page
// =========================================================================
INT_PTR CALLBACK loggingProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* cfg = reinterpret_cast<ServerConfig*>(GetWindowLongPtrW(dlg, GWLP_USERDATA));
    switch (msg) {
        case WM_INITDIALOG: {
            SetWindowLongPtrW(dlg, GWLP_USERDATA, lp);
            cfg = reinterpret_cast<ServerConfig*>(lp);
            winutil::setEditText(dlg, IDC_OPT_AUDIT,     cfg->auditCsv);
            winutil::setEditText(dlg, IDC_OPT_FILE_ROOT, cfg->fileRoot);
            return TRUE;
        }
        case WM_COMMAND: {
            switch (LOWORD(wp)) {
                case IDC_OPT_AUDIT_BROWSE: {
                    auto f = winutil::browseSaveFile(dlg, L"Audit log path",
                        L"CSV (*.csv)\0*.csv\0All files\0*.*\0");
                    if (!f.empty()) winutil::setEditText(dlg, IDC_OPT_AUDIT, f);
                    return TRUE;
                }
                case IDC_OPT_ROOT_BROWSE: {
                    auto f = winutil::browseFolder(dlg, L"File-transfer sandbox root");
                    if (!f.empty()) winutil::setEditText(dlg, IDC_OPT_FILE_ROOT, f);
                    return TRUE;
                }
            }
            break;
        }
        case WM_OPT_SAVE: {
            if (!cfg) return TRUE;
            cfg->auditCsv = winutil::getEditText(dlg, IDC_OPT_AUDIT);
            cfg->fileRoot = winutil::getEditText(dlg, IDC_OPT_FILE_ROOT);
            return TRUE;
        }
    }
    return FALSE;
}

// =========================================================================
// Parent Options dialog
// =========================================================================
INT_PTR CALLBACK optionsProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* st = reinterpret_cast<Parent*>(GetWindowLongPtrW(dlg, GWLP_USERDATA));
    switch (msg) {
        case WM_INITDIALOG: {
            SetWindowLongPtrW(dlg, GWLP_USERDATA, lp);
            st = reinterpret_cast<Parent*>(lp);

            HWND tab = GetDlgItem(dlg, IDC_OPT_TAB);
            TCITEMW it{};
            it.mask = TCIF_TEXT;
            const wchar_t* names[3] = {L"General", L"IP Filter", L"Logging"};
            for (int i = 0; i < 3; ++i) {
                it.pszText = const_cast<wchar_t*>(names[i]);
                TabCtrl_InsertItem(tab, i, &it);
            }

            HINSTANCE hi = GetModuleHandleW(nullptr);
            LPARAM cfgPtr = reinterpret_cast<LPARAM>(st->cfg);
            st->pages[0] = CreateDialogParamW(hi, MAKEINTRESOURCEW(IDD_OPT_GENERAL),
                                              dlg, generalProc, cfgPtr);
            st->pages[1] = CreateDialogParamW(hi, MAKEINTRESOURCEW(IDD_OPT_FILTER),
                                              dlg, filterProc, cfgPtr);
            st->pages[2] = CreateDialogParamW(hi, MAKEINTRESOURCEW(IDD_OPT_LOGGING),
                                              dlg, loggingProc, cfgPtr);

            // Position pages inside the tab control's display area.
            RECT rc;
            GetWindowRect(tab, &rc);
            TabCtrl_AdjustRect(tab, FALSE, &rc); // shrink to client display area
            POINT tl{rc.left, rc.top}, br{rc.right, rc.bottom};
            ScreenToClient(dlg, &tl);
            ScreenToClient(dlg, &br);
            const int x = tl.x, y = tl.y, w = br.x - tl.x, h = br.y - tl.y;
            for (int i = 0; i < 3; ++i) {
                SetWindowPos(st->pages[i], HWND_TOP, x, y, w, h, SWP_NOACTIVATE);
            }
            ShowWindow(st->pages[0], SW_SHOW);
            ShowWindow(st->pages[1], SW_HIDE);
            ShowWindow(st->pages[2], SW_HIDE);

            winutil::centerDialog(dlg);
            return TRUE;
        }

        case WM_NOTIFY: {
            auto* hdr = reinterpret_cast<NMHDR*>(lp);
            if (hdr && hdr->idFrom == IDC_OPT_TAB && hdr->code == TCN_SELCHANGE) {
                int sel = TabCtrl_GetCurSel(GetDlgItem(dlg, IDC_OPT_TAB));
                for (int i = 0; i < 3; ++i) {
                    ShowWindow(st->pages[i], i == sel ? SW_SHOW : SW_HIDE);
                }
                return TRUE;
            }
            break;
        }

        case WM_COMMAND: {
            switch (LOWORD(wp)) {
                case IDOK:
                    if (st) {
                        for (int i = 0; i < 3; ++i)
                            if (st->pages[i]) SendMessageW(st->pages[i], WM_OPT_SAVE, 0, 0);
                    }
                    EndDialog(dlg, IDOK);
                    return TRUE;
                case IDCANCEL:
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

bool showOptionsDialog(HWND owner, ServerConfig& cfg) {
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_TAB_CLASSES | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);

    Parent st;
    st.cfg = &cfg;
    HINSTANCE hi = GetModuleHandleW(nullptr);
    INT_PTR r = DialogBoxParamW(hi, MAKEINTRESOURCEW(IDD_OPTIONS), owner, optionsProc,
                                reinterpret_cast<LPARAM>(&st));
    return r == IDOK;
}

} // namespace rp
