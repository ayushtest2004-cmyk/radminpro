#include "ui/UsersDialog.h"

#include "security/PasswordStore.h"
#include "ui/WinUtil.h"
#include "ui/resource.h"

#include <windows.h>
#include <commctrl.h>

#include <optional>
#include <vector>

namespace rp {

namespace {

// ----- Right-bit / checkbox map ------------------------------------------
struct RightCheck { int id; uint32_t bit; };
constexpr RightCheck kRightChecks[] = {
    {IDC_RIGHT_ALL,      R_AllAccess},
    {IDC_RIGHT_CONTROL,  R_RemoteScreenControl},
    {IDC_RIGHT_VIEW,     R_RemoteScreenView},
    {IDC_RIGHT_TELNET,   R_Telnet},
    {IDC_RIGHT_FILE,     R_FileTransfer},
    {IDC_RIGHT_REDIRECT, R_Redirect},
    {IDC_RIGHT_CHAT,     R_Chat},
    {IDC_RIGHT_VOICE,    R_VoiceChat},
    {IDC_RIGHT_MSG,      R_SendMessage},
    {IDC_RIGHT_SHUTDOWN, R_Shutdown},
};

// =========================================================================
// Add User sub-dialog
// =========================================================================
struct AddState { std::optional<UserRecord> result; };

INT_PTR CALLBACK addUserProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* st = reinterpret_cast<AddState*>(GetWindowLongPtrW(dlg, GWLP_USERDATA));
    switch (msg) {
        case WM_INITDIALOG:
            SetWindowLongPtrW(dlg, GWLP_USERDATA, lp);
            winutil::centerDialog(dlg);
            SetFocus(GetDlgItem(dlg, IDC_ADD_USERNAME));
            return FALSE;
        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case IDOK: {
                    std::string name  = winutil::getEditText(dlg, IDC_ADD_USERNAME);
                    std::string pass1 = winutil::getEditText(dlg, IDC_ADD_PASS1);
                    std::string pass2 = winutil::getEditText(dlg, IDC_ADD_PASS2);
                    if (name.empty()) {
                        winutil::messageBoxError(dlg, "Username cannot be empty.");
                        return TRUE;
                    }
                    if (pass1.empty()) {
                        winutil::messageBoxError(dlg, "Password cannot be empty.");
                        return TRUE;
                    }
                    if (pass1 != pass2) {
                        winutil::messageBoxError(dlg, "Passwords do not match.");
                        secureZero(pass1); secureZero(pass2);
                        return TRUE;
                    }
                    secureZero(pass2);
                    UserRecord u;
                    u.username = name;
                    try {
                        u.argon2Hash = PasswordStore::hash(std::move(pass1));
                    } catch (const std::exception& e) {
                        winutil::messageBoxError(dlg, std::string("hash failed: ") + e.what());
                        return TRUE;
                    }
                    u.rights = R_None;
                    if (st) st->result = std::move(u);
                    EndDialog(dlg, IDOK);
                    return TRUE;
                }
                case IDCANCEL:
                    EndDialog(dlg, IDCANCEL);
                    return TRUE;
            }
            break;
        case WM_CLOSE:
            EndDialog(dlg, IDCANCEL);
            return TRUE;
    }
    return FALSE;
}

std::optional<UserRecord> showAddUserDialog(HWND owner) {
    AddState st;
    HINSTANCE hi = GetModuleHandleW(nullptr);
    DialogBoxParamW(hi, MAKEINTRESOURCEW(IDD_ADD_USER), owner, addUserProc,
                    reinterpret_cast<LPARAM>(&st));
    return st.result;
}

// =========================================================================
// Users + Rights dialog
// =========================================================================
struct UState {
    ServerConfig* cfg = nullptr;
    std::vector<UserRecord> users; // working copy
    int selected = -1;
};

static void populateList(HWND lst, const std::vector<UserRecord>& users) {
    ListView_DeleteAllItems(lst);
    for (size_t i = 0; i < users.size(); ++i) {
        std::wstring w = winutil::widen(users[i].username);
        LVITEMW it{};
        it.mask     = LVIF_TEXT;
        it.iItem    = static_cast<int>(i);
        it.pszText  = w.data();
        ListView_InsertItem(lst, &it);
    }
}

static void rightsToChecks(HWND dlg, uint32_t rights) {
    for (const auto& r : kRightChecks) {
        winutil::setChecked(dlg, r.id, (rights & r.bit) != 0);
    }
}

static uint32_t checksToRights(HWND dlg) {
    uint32_t r = 0;
    for (const auto& rc : kRightChecks) {
        if (winutil::isChecked(dlg, rc.id)) r |= rc.bit;
    }
    return r;
}

static void enableRights(HWND dlg, bool on) {
    for (const auto& r : kRightChecks) winutil::enableCtrl(dlg, r.id, on);
}

INT_PTR CALLBACK usersProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* st = reinterpret_cast<UState*>(GetWindowLongPtrW(dlg, GWLP_USERDATA));
    switch (msg) {
        case WM_INITDIALOG: {
            SetWindowLongPtrW(dlg, GWLP_USERDATA, lp);
            st = reinterpret_cast<UState*>(lp);

            HWND lst = GetDlgItem(dlg, IDC_USERS_LIST);
            ListView_SetExtendedListViewStyle(lst, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
            LVCOLUMNW col{};
            col.mask    = LVCF_TEXT | LVCF_WIDTH;
            col.pszText = const_cast<LPWSTR>(L"User");
            col.cx      = 300;
            ListView_InsertColumn(lst, 0, &col);

            st->users = st->cfg->users; // working copy
            populateList(lst, st->users);
            enableRights(dlg, false);
            rightsToChecks(dlg, 0);
            winutil::centerDialog(dlg);
            return TRUE;
        }

        case WM_NOTIFY: {
            auto* hdr = reinterpret_cast<NMHDR*>(lp);
            if (hdr && hdr->idFrom == IDC_USERS_LIST && hdr->code == LVN_ITEMCHANGED) {
                auto* nm = reinterpret_cast<NMLISTVIEW*>(lp);
                if (nm->uChanged & LVIF_STATE) {
                    if (nm->uNewState & LVIS_SELECTED) {
                        st->selected = nm->iItem;
                        if (st->selected >= 0 &&
                            st->selected < static_cast<int>(st->users.size())) {
                            enableRights(dlg, true);
                            rightsToChecks(dlg, st->users[st->selected].rights);
                        }
                    } else if (nm->uOldState & LVIS_SELECTED) {
                        // selection cleared
                        if (ListView_GetSelectedCount(GetDlgItem(dlg, IDC_USERS_LIST)) == 0) {
                            st->selected = -1;
                            enableRights(dlg, false);
                            rightsToChecks(dlg, 0);
                        }
                    }
                }
                return TRUE;
            }
            break;
        }

        case WM_COMMAND: {
            const WORD id = LOWORD(wp);

            // any rights checkbox -> sync into the working copy
            for (const auto& rc : kRightChecks) {
                if (id == rc.id && st && st->selected >= 0 &&
                    st->selected < static_cast<int>(st->users.size())) {
                    st->users[st->selected].rights = checksToRights(dlg);
                    return TRUE;
                }
            }

            switch (id) {
                case IDC_USERS_ADD: {
                    auto u = showAddUserDialog(dlg);
                    if (u) {
                        st->users.push_back(*u);
                        populateList(GetDlgItem(dlg, IDC_USERS_LIST), st->users);
                    }
                    return TRUE;
                }
                case IDC_USERS_REMOVE: {
                    if (st->selected < 0 ||
                        st->selected >= static_cast<int>(st->users.size())) return TRUE;
                    if (!winutil::messageBoxYesNo(dlg,
                            "Remove user '" + st->users[st->selected].username + "'?"))
                        return TRUE;
                    st->users.erase(st->users.begin() + st->selected);
                    st->selected = -1;
                    populateList(GetDlgItem(dlg, IDC_USERS_LIST), st->users);
                    enableRights(dlg, false);
                    rightsToChecks(dlg, 0);
                    return TRUE;
                }
                case IDOK:
                    if (st) st->cfg->users = std::move(st->users);
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

bool showUsersDialog(HWND owner, ServerConfig& cfg) {
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);

    UState st;
    st.cfg = &cfg;
    HINSTANCE hi = GetModuleHandleW(nullptr);
    INT_PTR r = DialogBoxParamW(hi, MAKEINTRESOURCEW(IDD_USERS), owner, usersProc,
                                reinterpret_cast<LPARAM>(&st));
    return r == IDOK;
}

} // namespace rp
