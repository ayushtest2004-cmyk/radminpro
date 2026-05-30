#include "ui/WinUtil.h"

#include <commdlg.h>
#include <shlobj.h>

namespace rp { namespace winutil {

std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

std::string narrow(const std::wstring& s) {
    if (s.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string a(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &a[0], n, nullptr, nullptr);
    return a;
}

std::string getEditText(HWND dlg, int id) {
    HWND ctl = GetDlgItem(dlg, id);
    if (!ctl) return "";
    int len = GetWindowTextLengthW(ctl);
    if (len <= 0) return "";
    std::wstring w(static_cast<size_t>(len) + 1, L'\0');
    int got = GetWindowTextW(ctl, &w[0], len + 1);
    w.resize(got);
    return narrow(w);
}
void setEditText(HWND dlg, int id, const std::string& s) {
    SetDlgItemTextW(dlg, id, widen(s).c_str());
}

bool isChecked(HWND dlg, int id) { return IsDlgButtonChecked(dlg, id) == BST_CHECKED; }
void setChecked(HWND dlg, int id, bool on) {
    CheckDlgButton(dlg, id, on ? BST_CHECKED : BST_UNCHECKED);
}
void enableCtrl(HWND dlg, int id, bool on) {
    EnableWindow(GetDlgItem(dlg, id), on ? TRUE : FALSE);
}

static std::string browseFile(HWND owner, const wchar_t* title, const wchar_t* filter, bool save) {
    wchar_t buf[MAX_PATH] = {0};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = owner;
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = title;
    ofn.lpstrFilter = filter;
    ofn.Flags = OFN_HIDEREADONLY | OFN_NOCHANGEDIR |
                (save ? OFN_OVERWRITEPROMPT
                      : (OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST));
    BOOL ok = save ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn);
    return ok ? narrow(buf) : std::string();
}
std::string browseOpenFile(HWND owner, const wchar_t* title, const wchar_t* filter) {
    return browseFile(owner, title, filter, false);
}
std::string browseSaveFile(HWND owner, const wchar_t* title, const wchar_t* filter) {
    return browseFile(owner, title, filter, true);
}

std::string browseFolder(HWND owner, const wchar_t* title) {
    BROWSEINFOW bi{};
    bi.hwndOwner = owner;
    bi.lpszTitle = title;
    bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return "";
    wchar_t path[MAX_PATH] = {0};
    if (!SHGetPathFromIDListW(pidl, path)) { CoTaskMemFree(pidl); return ""; }
    CoTaskMemFree(pidl);
    return narrow(path);
}

void messageBoxError(HWND owner, const std::string& msg) {
    MessageBoxW(owner, widen(msg).c_str(), L"radminpro", MB_ICONERROR | MB_OK);
}
void messageBoxInfo(HWND owner, const std::string& msg) {
    MessageBoxW(owner, widen(msg).c_str(), L"radminpro", MB_ICONINFORMATION | MB_OK);
}
bool messageBoxYesNo(HWND owner, const std::string& msg) {
    return MessageBoxW(owner, widen(msg).c_str(), L"radminpro",
                       MB_ICONQUESTION | MB_YESNO) == IDYES;
}

void centerDialog(HWND dlg) {
    RECT rc; GetWindowRect(dlg, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    int sx = GetSystemMetrics(SM_CXSCREEN);
    int sy = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(dlg, nullptr, (sx - w) / 2, (sy - h) / 2, 0, 0,
                 SWP_NOZORDER | SWP_NOSIZE | SWP_NOACTIVATE);
}

}} // namespace rp::winutil
