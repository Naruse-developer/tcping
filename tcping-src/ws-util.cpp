/***********************************************************************
tcping.exe -- A tcp probe utility
Copyright (C) 2005 Eli Fulkerson

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

----------------------------------------------------------------------

Other license terms may be negotiable.  Contact the author if you would
like a copy that is licensed differently.

Contact information (as well as this program) lives at http://www.elifulkerson.com

----------------------------------------------------------------------

This application includes public domain code from the Winsock Programmer's FAQ:
  http://www.tangentsoft.net/wskfaq/
... and a big thank you to the maintainers and contributers therein.

***********************************************************************/

#include "ws-util.h"

#include <iostream>
#include <algorithm>
#include <strstream>

using namespace std;

#if !defined(_WINSOCK2API_)
// Winsock 2 header defines this, but Winsock 1.1 header doesn't.  In
// the interest of not requiring the Winsock 2 SDK which we don't really
// need, we'll just define this one constant ourselves.
#define SD_SEND 1
#endif


//// Constants /////////////////////////////////////////////////////////

const int kBufferSize = 1024;


//// Statics ///////////////////////////////////////////////////////////

// List of Winsock error constants mapped to an interpretation string.
// Note that this list must remain sorted by the error constants'
// values, because we do a binary search on the list when looking up
// items.
static struct ErrorEntry {
    int nID;
    const char* pcMessage;

    ErrorEntry(int id, const char* pc = 0) :
        nID(id),
        pcMessage(pc) {
    }

    bool operator<(const ErrorEntry& rhs) {
        return nID < rhs.nID;
    }
} gaErrorList[] = {
    ErrorEntry(0,                  "無錯誤"),
    ErrorEntry(WSAEINTR,           "系統調用中斷"),
    ErrorEntry(WSAEBADF,           "檔案編號錯誤"),
    ErrorEntry(WSAEACCES,          "沒有權限"),
    ErrorEntry(WSAEFAULT,          "地址錯誤"),
    ErrorEntry(WSAEINVAL,          "Invalid argument"),
    ErrorEntry(WSAEMFILE,          "過多開放的網絡套接字"),
    ErrorEntry(WSAEWOULDBLOCK,     "Operation would block"),
    ErrorEntry(WSAEINPROGRESS,     "正在進行操作"),
    ErrorEntry(WSAEALREADY,        "操作已在進行中"),
    ErrorEntry(WSAENOTSOCK,        "非套接字上的套接字操作"),
    ErrorEntry(WSAEDESTADDRREQ,    "需要目的地地址"),
    ErrorEntry(WSAEMSGSIZE,        "訊息過長"),
    ErrorEntry(WSAEPROTOTYPE,      "套接字的協議錯誤類型"),
    ErrorEntry(WSAENOPROTOOPT,     "錯誤的協議選項"),
    ErrorEntry(WSAEPROTONOSUPPORT, "不支持協議"),
    ErrorEntry(WSAESOCKTNOSUPPORT, "不支援網絡套接字類型"),
    ErrorEntry(WSAEOPNOTSUPP,      "套接字不支持該操作"),
    ErrorEntry(WSAEPFNOSUPPORT,    "不支持協議族"),
    ErrorEntry(WSAEAFNOSUPPORT,    "不支持地址族"),
    ErrorEntry(WSAEADDRINUSE,      "地址已被使用"),
    ErrorEntry(WSAEADDRNOTAVAIL,   "無法分配請求的地址"),
    ErrorEntry(WSAENETDOWN,        "網絡中斷"),
    ErrorEntry(WSAENETUNREACH,     "網絡不可達"),
    ErrorEntry(WSAENETRESET,       "網絡連接重置"),
    ErrorEntry(WSAECONNABORTED,    "軟件導致連接中止"),
    ErrorEntry(WSAECONNRESET,      "對等連接重置"),
    ErrorEntry(WSAENOBUFS,         "沒有可用的緩衝區空間"),
    ErrorEntry(WSAEISCONN,         "網路套接字已連接"),
    ErrorEntry(WSAENOTCONN,        "網路套接字未連接"),
    ErrorEntry(WSAESHUTDOWN,       "網路套接字關閉後無法發送"),
    ErrorEntry(WSAETOOMANYREFS,    "引用過多，無法拼接"),
    ErrorEntry(WSAETIMEDOUT,       "連接超時"),
    ErrorEntry(WSAECONNREFUSED,    "拒絕連接"),
    ErrorEntry(WSAELOOP,           "Too many levels of symbolic links"),
    ErrorEntry(WSAENAMETOOLONG,    "文件名太長"),
    ErrorEntry(WSAEHOSTDOWN,       "主機已關閉"),
    ErrorEntry(WSAEHOSTUNREACH,    "沒有到主機的路由"),
    ErrorEntry(WSAENOTEMPTY,       "目錄不為空"),
    ErrorEntry(WSAEPROCLIM,        "處理請求太多"),
    ErrorEntry(WSAEUSERS,          "用戶太多"),
    ErrorEntry(WSAEDQUOT,          "超出配額"),
    ErrorEntry(WSAESTALE,          "NFS共享無法掛載"),
    ErrorEntry(WSAEREMOTE,         "Too many levels of remote in path"),
    ErrorEntry(WSASYSNOTREADY,     "網絡系統不可用"),
    ErrorEntry(WSAVERNOTSUPPORTED, "Winsock版本超出範圍"),
    ErrorEntry(WSANOTINITIALISED,  "尚未調用WSAStartup"),
    ErrorEntry(WSAEDISCON,         "正在關閉"),
    ErrorEntry(WSAHOST_NOT_FOUND,  "未找到主機名"),
    ErrorEntry(WSANO_DATA,         "找不到該類型的主機數據")
};
const int kNumMessages = sizeof(gaErrorList) / sizeof(ErrorEntry);


//// WSAGetLastErrorMessage ////////////////////////////////////////////
// A function similar in spirit to Unix's perror() that tacks a canned
// interpretation of the value of WSAGetLastError() onto the end of a
// passed string, separated by a ": ".  Generally, you should implement
// smarter error handling than this, but for default cases and simple
// programs, this function is sufficient.
//
// This function returns a pointer to an internal static buffer, so you
// must copy the data from this function before you call it again.  It
// follows that this function is also not thread-safe.

const char* WSAGetLastErrorMessage(const char* pcMessagePrefix,
                                   int nErrorID /* = 0 */) {
    // Build basic error string
    static char acErrorBuffer[256];
    ostrstream outs(acErrorBuffer, sizeof(acErrorBuffer));
    outs << pcMessagePrefix;

    // Tack appropriate canned message onto end of supplied message
    // prefix. Note that we do a binary search here: gaErrorList must be
    // sorted by the error constant's value.
    ErrorEntry* pEnd = gaErrorList + kNumMessages;
    ErrorEntry Target(nErrorID ? nErrorID : WSAGetLastError());
    ErrorEntry* it = lower_bound(gaErrorList, pEnd, Target);
    if ((it != pEnd) && (it->nID == Target.nID)) {
        outs << it->pcMessage;
    } else {
        // Didn't find error in list, so make up a generic one
        outs << "未知錯誤";
    }
    outs << " (" << Target.nID << ")";


    // Finish error message off and return it.
    outs << ends;
    acErrorBuffer[sizeof(acErrorBuffer) - 1] = '\0';
    return acErrorBuffer;
}


//// ShutdownConnection ////////////////////////////////////////////////
// Gracefully shuts the connection sd down.  Returns true if we're
// successful, false otherwise.

bool ShutdownConnection(SOCKET sd) {
    // Disallow any further data sends.  This will tell the other side
    // that we want to go away now.  If we skip this step, we don't
    // shut the connection down nicely.
    if (shutdown(sd, SD_SEND) == SOCKET_ERROR) {
        closesocket(sd);
        return false;
    }

    // Receive any extra data still sitting on the socket.  After all
    // data is received, this call will block until the remote host
    // acknowledges the TCP control packet sent by the shutdown above.
    // Then we'll get a 0 back from recv, signalling that the remote
    // host has closed its side of the connection.
    char acReadBuffer[kBufferSize];
    while (1) {
        int nNewBytes = recv(sd, acReadBuffer, kBufferSize, 0);
        if (nNewBytes == SOCKET_ERROR) {
            closesocket(sd);
            return false;
        } else if (nNewBytes != 0) {
            //    cerr << endl << "FYI, received " << nNewBytes <<
            //            " unexpected bytes during shutdown." << acReadBuffer << endl;
            cout << " (" << nNewBytes << " 讀取字節)";
        } else {
            // Okay, we're done!
            break;
        }
    }

    // Close the socket.
    if (closesocket(sd) == SOCKET_ERROR) {
        return false;
    }

    return true;
}

