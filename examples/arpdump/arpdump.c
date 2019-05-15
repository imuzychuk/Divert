/*
 * netdump.c
 * (C) 2018, all rights reserved,
 *
 * This file is part of WinDivert.
 *
 * WinDivert is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * WinDivert is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * DESCRIPTION:
 * This is a simple ARP monitor.  It uses a WinDivert handle in ARP SNIFF mode.
 *
 * usage: arpdump.exe interface-name [priority]
 *
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

#define MAXBUF  0xFFFF

static volatile BOOL g_exit = FALSE;


static BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType)
{
  g_exit = TRUE;
  return TRUE;
}


/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    HANDLE handle, console;
    UINT i;
    INT16 priority = 0;
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    PWINDIVERT_ICMPHDR icmp_header;
    PWINDIVERT_ICMPV6HDR icmpv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;
    const char *err_str;
    LARGE_INTEGER base, freq;
    double time_passed;
    console = GetStdHandle(STD_OUTPUT_HANDLE);

    //SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    // Sniff ARP packets:
    handle = WinDivertARPSniffOpen(1000);
    if (handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: failed to open the WinDivert ARP Sniff device (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Sleep(55000);
    while (!g_exit)
    {
        // Read a matching packet.
        if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
        {
            fprintf(stderr, "warning: failed to read packet (%d)\n",
                GetLastError());
            continue;
        }

        printf("\n");
        printf("Received ARP packet with len: %u. direction - %s\n",
               packet_len, addr.Direction == WINDIVERT_DIRECTION_OUTBOUND ? "outbound" : "inbound");
        for (int i = 0; i < packet_len; i++)
        {
            if (i % 16 == 0 && i)
            {
                printf("\n");
            }
            printf("%02X ", packet[i]);
        }
        printf("\n");
    }

    WinDivertARPSniffClose(handle);
}
