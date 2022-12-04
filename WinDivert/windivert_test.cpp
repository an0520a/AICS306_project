#include <iostream>
#include "windivert.h"

int main()
{
    HANDLE hSocketLayer = WinDivertOpen("true", WINDIVERT_LAYER_FLOW, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

    if (hSocketLayer == INVALID_HANDLE_VALUE)
    {
        std::cout << "error" << GetLastError() << std::endl;
        return 1;
    }
    
    WINDIVERT_ADDRESS addr;

    if (WinDivertRecv(hSocketLayer, nullptr, 0, nullptr, &addr) == false)
    {
        std::cout << "error" << GetLastError() << std::endl;
        return 1;
    }
    
    std::cout << addr.Timestamp << std::endl
              << addr.Layer << std::endl
              << addr.Event << std::endl
              << addr.Sniffed << std::endl
              << addr.Outbound << std::endl
              << addr.Loopback << std::endl
              << addr.Impostor << std::endl
              << addr.IPv6 << std::endl
              << addr.IPChecksum << std::endl
              << addr.IPChecksum << std::endl
              << addr.TCPChecksum << std::endl
              << addr.UDPChecksum << std::endl;

    std::cout << std::endl;

    char local_addr[128];
    char remote_addr[128];

    WinDivertHelperFormatIPv4Address(addr.Flow.LocalAddr[0], local_addr, 128);
    WinDivertHelperFormatIPv4Address(addr.Flow.RemoteAddr[0], remote_addr, 128);

    std::cout << addr.Flow.EndpointId << std::endl
               << addr.Flow.ParentEndpointId << std::endl
               << addr.Flow.ProcessId << std::endl
               << local_addr << std::endl
               << remote_addr << std::endl
               << addr.Flow.LocalPort << std::endl
               << addr.Flow.RemotePort << std::endl
               << addr.Flow.Protocol << std::endl;
    
    std::cout << sizeof(addr) << std::endl;
    std::cout << std::endl;

    std::cout << sizeof(addr.Timestamp) << std::endl
              << sizeof(addr.Flow) << std::endl
              << sizeof(addr.Flow) << std::endl
              << sizeof(addr.Flow) << std::endl
              << sizeof(addr.Flow) << std::endl
              << sizeof(addr.Reserved3) << std::endl;
}
