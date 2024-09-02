#pragma once
#include <string>
#include <vector>
#include <Packet.h>


namespace Filter
{
	struct PacketInfo
	{
		CString PacketTimeStr;
		CString SrcIP;
		CString DstIP;
		CString Protocol;
		CString Length;
		CString Info;;
	};
	class FilterFunction
	{
	public:
		static PacketInfo FilterdPacketInfo(pcpp::RawPacket* pRawPacket);
	};
}