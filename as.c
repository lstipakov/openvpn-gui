/*
 *  OpenVPN-GUI -- A Windows GUI for OpenVPN.
 *
 *  Copyright (C) 2021 Lev Stipakov <lstipakov@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <windows.h>
#include <wininet.h>
#include <stdlib.h>

#include "config.h"
#include "localization.h"
#include "main.h"
#include "misc.h"
#include "openvpn.h"
#include "openvpn-gui-res.h"
#include "save_pass.h"

#define URL_LEN 1024
#define PROFILE_NAME_LEN 128
#define READ_CHUNK_LEN 65536

#define PROFILE_NAME_TOKEN "# OVPN_ACCESS_SERVER_PROFILE="
#define FRIENDLY_NAME_TOKEN "# OVPN_ACCESS_SERVER_FRIENDLY_NAME="

/**
 * Extract profile name from profile content.
 *
 * Profile name is either (sorted in priority order):
 * - value of OVPN_ACCESS_SERVER_FRIENDLY_NAME
 * - value of OVPN_ACCESS_SERVER_PROFILE
 * - URL
 *
 * @param profile profile content
 * @param url profile URL, might be used for name
 * @param out_name extracted profile name
 * @param out_name_length max length of out_name char array
 */
void
ExtractProfileName(const CHAR* profile, const CHAR* url, WCHAR* out_name, size_t out_name_length)
{
    CHAR friendly_name[PROFILE_NAME_LEN] = { 0 };
    CHAR profile_name[PROFILE_NAME_LEN] = { 0 };

    /* strdup() modifies string, need to make a copy */
    CHAR* buf = _strdup(profile);

    CHAR* pch = NULL;
    pch = strtok(buf, "\r\n");

    while (pch != NULL) {
        if (strbegins(pch, PROFILE_NAME_TOKEN))
            strcpy(profile_name, pch + strlen(PROFILE_NAME_TOKEN));
        else if (strbegins(pch, FRIENDLY_NAME_TOKEN))
            strcpy(profile_name, pch + strlen(FRIENDLY_NAME_TOKEN));

        pch = strtok(NULL, "\r\n");
    }

    if (strlen(friendly_name) > 0)
        _snwprintf(out_name, out_name_length, L"%hs.ovpn", friendly_name);
    else if (strlen(profile_name) > 0)
        _snwprintf(out_name, out_name_length, L"%hs.ovpn", profile_name);
    else
        _snwprintf(out_name, out_name_length, L"%hs.ovpn", url);

    /* sanitize profile name */
    while (*out_name) {
        WCHAR c = *out_name;
        if (!iswalnum(c) && c != L'_' && c != L'.' && c != L' ' && c != L'@')
            *out_name = L'_';
        ++out_name;
    }

    free(buf);
}

void
ShowWinInetError(HANDLE hWnd)
{
    CHAR err[256] = { 0 };
    FormatMessageA(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM, GetModuleHandleA("wininet.dll"),
        GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), err, _countof(err), NULL);
    ShowLocalizedMsgEx(MB_OK, hWnd, _T(PACKAGE_NAME), IDS_ERR_AS_IMPORT_PROFILE, GetLastError(), err);
}

/**
 * Download profile from AS and save it to a special-named file
 * in user's TMP directory.
 *
 * @param handle handle of window which initiated download
 * @param host AS hostname
 * @param username username used for HTTP basic auth
 * @param password password used for HTTP basic auth
 * @param autologin should autologn profile be used
 * @param out_path full path to where profile is downloaded. Value assigned by this function.
 */
BOOL
DownloadProfile(HANDLE hWnd, const CHAR* host, const CHAR* username, const CHAR* password, BOOL autologin, WCHAR* out_path)
{
    BOOL result = FALSE;
    CHAR* buf = NULL;
    HINTERNET hUrl = NULL;
    CHAR* up_b64 = NULL;

    HINTERNET hInternet = InternetOpenA("openvpn-gui/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        ShowWinInetError(hWnd);
        goto done;
    }

    CHAR url[URL_LEN] = {0};
    snprintf(url, URL_LEN, "%s%s/rest/%s?tls-cryptv2=1&action=import", strbegins(host, "http") ? "" : "https://",
        host, autologin ? "GetAutologin" : "GetUserlogin");

    /* prepare header for HTTP auth */
    CHAR up[USER_PASS_LEN*2 + 1] = {0};
    snprintf(up, sizeof(up), "%s:%s", username, password);
    Base64Encode(up, strlen(up), &up_b64);
    CHAR header[256] = {0};
    snprintf(header, sizeof(header), "Authorization: Basic %s", up_b64);

    /* wait cursor will be automatically reverted later */
    SetCursor(LoadCursorW(0, IDC_WAIT));

    DWORD flags = strbegins(url, "https://") ? INTERNET_FLAG_SECURE : 0;
    hUrl = InternetOpenUrlA(hInternet, url, header, strlen(header), flags, 0);
    if (hUrl == NULL) {
        ShowWinInetError(hWnd);
        goto done;
    }

    /* get http status code */
    DWORD statusCode = 0;
    DWORD length = sizeof(DWORD);
    HttpQueryInfoA(hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &length, NULL);
    if (statusCode != 200) {
        ShowLocalizedMsgEx(MB_OK, hWnd, _T(PACKAGE_NAME), IDS_ERR_AS_IMPORT_PROFILE, statusCode, "HTTP error");
        goto done;
    }

    /* download profile */
    SIZE_T pos = 0;
    SIZE_T size = READ_CHUNK_LEN;
    buf = calloc(1, size + 1);
    if (buf == NULL) {
        MessageBoxW(hWnd, L"Out of memory", _T(PACKAGE_NAME), MB_OK);
        goto done;
    }
    while (true) {
        DWORD bytesRead = 0;
        if (!InternetReadFile(hUrl, buf + pos, READ_CHUNK_LEN, &bytesRead)) {
            ShowWinInetError(hWnd);
            goto done;
        }
        if (bytesRead == 0) {
            size = pos;
            break;
        }

        buf[pos + bytesRead] = '\0';

        if (pos + bytesRead >= size) {
            size += READ_CHUNK_LEN;
            CHAR* ptr = realloc(buf, size + 1);
            if (!ptr) {
                MessageBoxW(hWnd, L"Out of memory", _T(PACKAGE_NAME), MB_OK);
                goto done;
            }
            buf = ptr;
        }

        pos += bytesRead;
    }

    WCHAR name[MAX_PATH] = {0};
    ExtractProfileName(buf, url, name, MAX_PATH);

    DWORD res = GetTempPathW(MAX_PATH, out_path);
    if (res == -1 || res > MAX_PATH) {
        MessageBoxW(hWnd, L"Failed to get TMP path", _T(PACKAGE_NAME), MB_OK);
        goto done;
    }
    wcscat(out_path, name);
    FILE* f = _wfopen(out_path, L"w");
    if (f == NULL) {
        MessageBoxW(hWnd, L"Unable to save downloaded profile", _T(PACKAGE_NAME), MB_OK);
        goto done;
    }
    fwrite(buf, sizeof(char), size, f);
    fclose(f);

    result = TRUE;

done:
    if (buf)
        free(buf);

    if (hUrl)
        InternetCloseHandle(hUrl);

    if (up_b64 != NULL)
        free(up_b64);

    if (hInternet)
        InternetCloseHandle(hInternet);

    return result;
}

INT_PTR CALLBACK
ImportProfileFromASDialogFunc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    CHAR url[URL_LEN] = {0};
    CHAR username[USER_PASS_LEN] = {0};
    CHAR password[USER_PASS_LEN] = {0};
    BOOL autologin = FALSE;

    switch (msg)
    {
    case WM_INITDIALOG:
        SetStatusWinIcon(hwndDlg, ID_ICO_APP);

        /* disable OK button by default - not disabled in resources */
        EnableWindow(GetDlgItem(hwndDlg, IDOK), FALSE);

        break;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_EDT_AUTH_USER:
        case ID_EDT_AUTH_PASS:
        case ID_EDT_URL:
            if (HIWORD(wParam) == EN_UPDATE) {
                /* enable OK button only if url, username, and password are filled */
                BOOL enableOK = GetWindowTextLengthA(GetDlgItem(hwndDlg, ID_EDT_URL))
                    && GetWindowTextLengthA(GetDlgItem(hwndDlg, ID_EDT_AUTH_USER))
                    && GetWindowTextLengthA(GetDlgItem(hwndDlg, ID_EDT_AUTH_PASS));
                EnableWindow(GetDlgItem(hwndDlg, IDOK), enableOK);
            }
            break;

        case IDOK:
            autologin = IsDlgButtonChecked(hwndDlg, ID_CHK_AUTOLOGIN) == BST_CHECKED;

            GetDlgItemTextA(hwndDlg, ID_EDT_URL, url, _countof(url));
            GetDlgItemTextA(hwndDlg, ID_EDT_AUTH_USER, username, _countof(username));
            GetDlgItemTextA(hwndDlg, ID_EDT_AUTH_PASS, password, _countof(password));

            WCHAR path[MAX_PATH] = { 0 };
            BOOL downloaded = DownloadProfile(hwndDlg, url, username, password, autologin, path);

            if (downloaded) {
                EndDialog(hwndDlg, LOWORD(wParam));

                ImportConfigFile(path);
                _wunlink(path);
            }
            return TRUE;

        case IDCANCEL:
            EndDialog(hwndDlg, LOWORD(wParam));
            return TRUE;
        }
        break;


    case WM_CLOSE:
        EndDialog(hwndDlg, LOWORD(wParam));
        return TRUE;

    case WM_NCDESTROY:
        break;
    }

    return FALSE;
}

void ImportConfigFromAS()
{
    LocalizedDialogBoxParam(ID_DLG_AS_PROFILE_IMPORT, ImportProfileFromASDialogFunc, 0);
}