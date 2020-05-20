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
    ErrorEntry(0,                  "�L���~"),
    ErrorEntry(WSAEINTR,           "�t�νեΤ��_"),
    ErrorEntry(WSAEBADF,           "�ɮ׽s�����~"),
    ErrorEntry(WSAEACCES,          "�S���v��"),
    ErrorEntry(WSAEFAULT,          "�a�}���~"),
    ErrorEntry(WSAEINVAL,          "Invalid argument"),
    ErrorEntry(WSAEMFILE,          "�L�h�}�񪺺����M���r"),
    ErrorEntry(WSAEWOULDBLOCK,     "Operation would block"),
    ErrorEntry(WSAEINPROGRESS,     "���b�i��ާ@"),
    ErrorEntry(WSAEALREADY,        "�ާ@�w�b�i�椤"),
    ErrorEntry(WSAENOTSOCK,        "�D�M���r�W���M���r�ާ@"),
    ErrorEntry(WSAEDESTADDRREQ,    "�ݭn�ت��a�a�}"),
    ErrorEntry(WSAEMSGSIZE,        "�T���L��"),
    ErrorEntry(WSAEPROTOTYPE,      "�M���r����ĳ���~����"),
    ErrorEntry(WSAENOPROTOOPT,     "���~����ĳ�ﶵ"),
    ErrorEntry(WSAEPROTONOSUPPORT, "�������ĳ"),
    ErrorEntry(WSAESOCKTNOSUPPORT, "���䴩�����M���r����"),
    ErrorEntry(WSAEOPNOTSUPP,      "�M���r������Ӿާ@"),
    ErrorEntry(WSAEPFNOSUPPORT,    "�������ĳ��"),
    ErrorEntry(WSAEAFNOSUPPORT,    "������a�}��"),
    ErrorEntry(WSAEADDRINUSE,      "�a�}�w�Q�ϥ�"),
    ErrorEntry(WSAEADDRNOTAVAIL,   "�L�k���t�ШD���a�}"),
    ErrorEntry(WSAENETDOWN,        "�������_"),
    ErrorEntry(WSAENETUNREACH,     "�������i�F"),
    ErrorEntry(WSAENETRESET,       "�����s�����m"),
    ErrorEntry(WSAECONNABORTED,    "�n��ɭP�s������"),
    ErrorEntry(WSAECONNRESET,      "�ﵥ�s�����m"),
    ErrorEntry(WSAENOBUFS,         "�S���i�Ϊ��w�İϪŶ�"),
    ErrorEntry(WSAEISCONN,         "�����M���r�w�s��"),
    ErrorEntry(WSAENOTCONN,        "�����M���r���s��"),
    ErrorEntry(WSAESHUTDOWN,       "�����M���r������L�k�o�e"),
    ErrorEntry(WSAETOOMANYREFS,    "�ޥιL�h�A�L�k����"),
    ErrorEntry(WSAETIMEDOUT,       "�s���W��"),
    ErrorEntry(WSAECONNREFUSED,    "�ڵ��s��"),
    ErrorEntry(WSAELOOP,           "Too many levels of symbolic links"),
    ErrorEntry(WSAENAMETOOLONG,    "���W�Ӫ�"),
    ErrorEntry(WSAEHOSTDOWN,       "�D���w����"),
    ErrorEntry(WSAEHOSTUNREACH,    "�S����D��������"),
    ErrorEntry(WSAENOTEMPTY,       "�ؿ�������"),
    ErrorEntry(WSAEPROCLIM,        "�B�z�ШD�Ӧh"),
    ErrorEntry(WSAEUSERS,          "�Τ�Ӧh"),
    ErrorEntry(WSAEDQUOT,          "�W�X�t�B"),
    ErrorEntry(WSAESTALE,          "NFS�@�ɵL�k����"),
    ErrorEntry(WSAEREMOTE,         "Too many levels of remote in path"),
    ErrorEntry(WSASYSNOTREADY,     "�����t�Τ��i��"),
    ErrorEntry(WSAVERNOTSUPPORTED, "Winsock�����W�X�d��"),
    ErrorEntry(WSANOTINITIALISED,  "�|���ե�WSAStartup"),
    ErrorEntry(WSAEDISCON,         "���b����"),
    ErrorEntry(WSAHOST_NOT_FOUND,  "�����D���W"),
    ErrorEntry(WSANO_DATA,         "�䤣����������D���ƾ�")
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
        outs << "�������~";
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
            cout << " (" << nNewBytes << " Ū���r�`)";
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

