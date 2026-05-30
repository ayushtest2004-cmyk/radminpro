#pragma once
//
// WinUtil - small helpers used by all dialogs. UTF-8 in C++, wide on the Win32
// side. Keeps the dialog procs short.
//
#include <windows.h>

#include <string>

namespace rp { namespace winutil {

std::wstring widen(const std::string& s);
std::string  narrow(const std::wstring& s);

std::string getEditText(HWND dlg, int id);
void        setEditText(HWND dlg, int id, const std::string& s);

bool isChecked(HWND dlg, int id);
void setChecked(HWND dlg, int id, bool on);

void enableCtrl(HWND dlg, int id, bool on);

// Modal File-Open / File-Save common dialogs. Filter format is the standard
// double-NUL-terminated Win32 string, e.g. L"PEM\0*.pem;*.crt\0All\0*.*\0".
std::string browseOpenFile(HWND owner, const wchar_t* title, const wchar_t* filter);
std::string browseSaveFile(HWND owner, const wchar_t* title, const wchar_t* filter);
std::string browseFolder  (HWND owner, const wchar_t* title);

void messageBoxError(HWND owner, const std::string& msg);
void messageBoxInfo (HWND owner, const std::string& msg);
bool messageBoxYesNo(HWND owner, const std::string& msg);

void centerDialog(HWND dlg);

}} // namespace rp::winutil
