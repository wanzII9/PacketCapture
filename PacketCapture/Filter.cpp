#include "pch.h"
#include "Filter.h"
#include "PacketCaptureDlg.h"
#include <PcapFilter.h>
#include <sstream> 
#include <SystemUtils.h>
#include <iomanip>
#include "Data.h"
#include "Protocol.h"


namespace Filter
{
	PacketInfo FilterFunction::FilterdPacketInfo(pcpp::RawPacket* packet)
	{
		PacketInfo packetinfo;
		pcpp::Packet parsedPacket(packet);

		//패킷의 타임스탬프 활용
		timespec packetTimestamp = packet->getPacketTimeStamp();
		struct tm* timeinfo = localtime(&packetTimestamp.tv_sec);
		CString formattedTime;
		formattedTime.Format(_T("%04d-%02d-%02d %02d:%02d:%02d.%03d"),
			timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday,
			timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec,
			static_cast<int>(packetTimestamp.tv_nsec / 10000));
		packetinfo.PacketTimeStr = formattedTime;

		packetinfo.Length.Format(_T("%u"), packet->getRawDataLen());


		if (parsedPacket.isPacketOfType(pcpp::IP))
		{
			packetinfo.SrcIP = CString(parsedPacket.getLayerOfType<pcpp::IPLayer>()->getSrcIPAddress().toString().c_str());
			packetinfo.DstIP = CString(parsedPacket.getLayerOfType<pcpp::IPLayer>()->getDstIPAddress().toString().c_str());
		}

		else if (parsedPacket.isPacketOfType(pcpp::ARP))
		{
			packetinfo.Protocol = _T("ARP");
			packetinfo.SrcIP = CString(parsedPacket.getLayerOfType<pcpp::ArpLayer>()->getSenderIpAddr().toString().c_str());
			packetinfo.DstIP = CString(parsedPacket.getLayerOfType<pcpp::ArpLayer>()->getTargetIpAddr().toString().c_str());

			if (pcpp::netToHost16(parsedPacket.getLayerOfType<pcpp::ArpLayer>()->getArpHeader()->opcode) == 1)
			{
				packetinfo.Info = _T("Who has ") + packetinfo.DstIP + _T("? Tell ") + packetinfo.SrcIP;

				CString target_hw_addr = CString(parsedPacket.getLayerOfType<pcpp::ArpLayer>()->getTargetMacAddress().toString().c_str());
				if (target_hw_addr == _T("00:00:00:00:00:00")) {
					packetinfo.DstIP = _T("Broadcast");
				}
			}
			else {
				CString sender_hw_addr = CString(parsedPacket.getLayerOfType<pcpp::ArpLayer>()->getSenderMacAddress().toString().c_str());
				packetinfo.Info = packetinfo.SrcIP + _T(" is at ") + sender_hw_addr;
			}

			return packetinfo;
		}

		if (parsedPacket.isPacketOfType(pcpp::ICMP))
		{
			packetinfo.Protocol = _T("ICMP");
			std::string ICMPTypeStr = Data::IcmpMessageTypeStr(parsedPacket.getLayerOfType<pcpp::IcmpLayer>()->getMessageType());
			packetinfo.Info.Format(_T("%S"), ICMPTypeStr.c_str());

			return packetinfo;
		}

		else if (parsedPacket.isPacketOfType(pcpp::ICMPv6))
		{
			packetinfo.Protocol = _T("ICMPv6");
			std::string ICMPv6TypeStr = Data::Icmpv6MessageTypeStr(parsedPacket.getLayerOfType <pcpp::IcmpV6Layer>()->getMessageType());
			packetinfo.Info.Format(_T("%S"), ICMPv6TypeStr.c_str());

			return packetinfo;
		}

		else if (parsedPacket.isPacketOfType(pcpp::TCP))
		{
			packetinfo.Info.Format(_T("%u -> %u"), ntohs(parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portSrc),
				ntohs(parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portDst));

			if (parsedPacket.getLastLayer() == parsedPacket.getLayerOfType<pcpp::TcpLayer>())
			{
				packetinfo.Protocol = _T("TCP");
				return packetinfo;
			}

			else if (parsedPacket.isPacketOfType(pcpp::HTTP))
			{
				packetinfo.Protocol = _T("HTTP");

				if (parsedPacket.isPacketOfType(pcpp::HTTPRequest))
				{
					pcpp::HttpRequestFirstLine* firstLine = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>()->getFirstLine();
					pcpp::HttpRequestLayer::HttpMethod methodEnum = firstLine->getMethod();
					std::string method = Data::httpMethodToString(methodEnum); // 문자열로 변환
					std::string uri = firstLine->getUri();
					std::string version = Data::httpVersionToString(firstLine->getVersion());

					std::string firstLineStr = method + " " + uri + " HTTP/" + version;
					packetinfo.Info.Format(_T("%S"), firstLineStr.c_str());
					return packetinfo;;
				}

				else if (parsedPacket.isPacketOfType(pcpp::HTTPResponse))
				{
					packetinfo.Protocol = _T("HTTP");

					pcpp::HttpResponseFirstLine* firstLine = parsedPacket.getLayerOfType<pcpp::HttpResponseLayer>()->getFirstLine();
					std::string version = Data::httpVersionToString(firstLine->getVersion());
					pcpp::HttpResponseStatusCode::Value value = firstLine->getStatusCode();
					std::string statusDescription = Data::httpStatusDescription(value);

					std::string firstLineStr = "HTTP/" + version + " " + std::to_string(value) + " " + statusDescription;
					packetinfo.Info.Format(_T("%S"), firstLineStr.c_str());
					return packetinfo;
				}
			}//HTTP

			else if (parsedPacket.isPacketOfType(pcpp::FTP))
			{
				packetinfo.Protocol = _T("FTP");
				return packetinfo;
			}

			else if (parsedPacket.isPacketOfType(pcpp::SSH))
			{
				packetinfo.Protocol = _T("SSH");
				return packetinfo;
			}

			else if (parsedPacket.isPacketOfType(pcpp::Telnet))
			{
				packetinfo.Protocol = _T("Telnet");
				return packetinfo;
			}

			else if (parsedPacket.isPacketOfType(pcpp::SSL))
			{
				packetinfo.Protocol = _T("TLS");
				return packetinfo;
			}
			else {
				packetinfo.Protocol = _T("TCP");
				return packetinfo;
			}
		}//TCP

		else if (parsedPacket.isPacketOfType(pcpp::UDP))
		{
			packetinfo.Info.Format(_T("%u -> %u"), ntohs(parsedPacket.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portSrc),
				ntohs(parsedPacket.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portDst));

			if (parsedPacket.getLastLayer() == parsedPacket.getLayerOfType<pcpp::PayloadLayer>())
			{
				packetinfo.Protocol = _T("UDP");
				return packetinfo;
			}

			else if (parsedPacket.isPacketOfType(pcpp::DHCP))
			{
				packetinfo.Protocol = _T("DHCP");
				return packetinfo;
			}

			else if (parsedPacket.isPacketOfType(pcpp::DNS))
			{
				packetinfo.Protocol = _T("DNS");
				return packetinfo;
			}

		}

		else if (parsedPacket.isPacketOfType(pcpp::IGMPv3))
		{
			std::string IGMPTypeStr = Data::IgmpTypeStr(parsedPacket.getLayerOfType<pcpp::IgmpLayer>()->getType());

			CString IGMPTypeStrCString(IGMPTypeStr.c_str());
			packetinfo.Info.Format(_T("%s"), IGMPTypeStrCString);
			packetinfo.Protocol = _T("IGMPv3");
			return packetinfo;
		}

		else if (parsedPacket.isPacketOfType(pcpp::IGMPv2))
		{
			std::string IGMPTypeStr = Data::IgmpTypeStr(parsedPacket.getLayerOfType<pcpp::IgmpLayer>()->getType());

			CString IGMPTypeStrCString(IGMPTypeStr.c_str());
			packetinfo.Info.Format(_T("%s"), IGMPTypeStrCString);
			packetinfo.Protocol = _T("IGMPv2");
			return packetinfo;
		}

		else if (parsedPacket.isPacketOfType(pcpp::IGMP))
		{
			std::string IGMPTypeStr = Data::IgmpTypeStr(parsedPacket.getLayerOfType<pcpp::IgmpLayer>()->getType());

			CString IGMPTypeStrCString(IGMPTypeStr.c_str());
			packetinfo.Info.Format(_T("%s"), IGMPTypeStrCString);
			packetinfo.Protocol = _T("IGMP");
		}

		else
		{
			packetinfo.Protocol = _T("Unknown");
		}
		return packetinfo;
	}
}