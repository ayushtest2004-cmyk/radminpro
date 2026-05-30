#pragma once
//
// resource.h - Win32 dialog / control / menu IDs shared between the RC and C++.
// Numbers are stable; do not renumber once shipped.
//

// ----- Dialogs ------------------------------------------------------------
#define IDD_CONNECT             101
#define IDD_OPTIONS             102
#define IDD_USERS               103
#define IDD_ADD_USER            104
#define IDD_ABOUT               105
// Options tab pages (child dialogs with DS_CONTROL)
#define IDD_OPT_GENERAL         110
#define IDD_OPT_FILTER          111
#define IDD_OPT_LOGGING         112

// ----- Menus / accelerators ----------------------------------------------
#define IDR_TRAY_MENU           200

// ----- Tray menu commands -------------------------------------------------
#define IDM_TRAY_OPTIONS        2001
#define IDM_TRAY_USERS          2002
#define IDM_TRAY_ABOUT          2003
#define IDM_TRAY_EXIT           2004

// ----- Connect dialog controls -------------------------------------------
#define IDC_CONN_HOST           1001
#define IDC_CONN_PORT           1002
#define IDC_CONN_DEFAULT_PORT   1003
#define IDC_CONN_USER           1004
#define IDC_CONN_PASS           1005
#define IDC_CONN_PIN            1006
#define IDC_CONN_CA             1007
#define IDC_CONN_CA_BROWSE      1008
#define IDC_CONN_VIEW           1009
#define IDC_CONN_CONTROL        1010
#define IDC_CONN_FILES          1011

// ----- Options dialog (host frame) ---------------------------------------
#define IDC_OPT_TAB             1100
// General page
#define IDC_OPT_BIND            1101
#define IDC_OPT_PORT            1102
#define IDC_OPT_USE_DEFAULT     1103
#define IDC_OPT_MAX_SESS        1104
#define IDC_OPT_CERT            1105
#define IDC_OPT_CERT_BROWSE     1106
#define IDC_OPT_KEY             1107
#define IDC_OPT_KEY_BROWSE      1108
#define IDC_OPT_MONITOR         1109
// IP Filter page
#define IDC_OPT_CIDR_LIST       1120
#define IDC_OPT_CIDR_EDIT       1121
#define IDC_OPT_CIDR_ADD        1122
#define IDC_OPT_CIDR_REMOVE     1123
// Logging page
#define IDC_OPT_AUDIT           1130
#define IDC_OPT_AUDIT_BROWSE    1131
#define IDC_OPT_FILE_ROOT       1132
#define IDC_OPT_ROOT_BROWSE     1133

// ----- Users dialog controls ---------------------------------------------
#define IDC_USERS_LIST          1200
#define IDC_USERS_ADD           1201
#define IDC_USERS_REMOVE        1202
#define IDC_USERS_RIGHTS_GROUP  1203
#define IDC_RIGHT_ALL           1210
#define IDC_RIGHT_VIEW          1211
#define IDC_RIGHT_CONTROL       1212
#define IDC_RIGHT_FILE          1213
#define IDC_RIGHT_CHAT          1214
#define IDC_RIGHT_MSG           1215
#define IDC_RIGHT_SHUTDOWN      1216
#define IDC_RIGHT_REDIRECT      1217
#define IDC_RIGHT_TELNET        1218
#define IDC_RIGHT_VOICE         1219

// ----- Add User dialog ----------------------------------------------------
#define IDC_ADD_USERNAME        1300
#define IDC_ADD_PASS1           1301
#define IDC_ADD_PASS2           1302

// ----- About --------------------------------------------------------------
#define IDC_ABOUT_TEXT          1400
