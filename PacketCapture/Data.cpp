#include "pch.h"
#include "Data.h"


CString Data::DexToBinary(CString _number) {
	CString result, temp1, temp2, temp3, temp4;

	temp1 = CString((std::to_string(_ttoi(_number) % 2)).c_str());
	_number = CString((std::to_string(_ttoi(_number) / 2)).c_str());
	temp2 = CString((std::to_string(_ttoi(_number) % 2)).c_str());
	_number = CString((std::to_string(_ttoi(_number) / 2)).c_str());
	temp3 = CString((std::to_string(_ttoi(_number) % 2)).c_str());
	temp4 = CString((std::to_string(_ttoi(_number) / 2)).c_str());

	result = temp4 + temp3 + temp2 + temp1;

	return result;
}

CString Data::HexToDec(CString _number) {
	wchar_t* end = NULL;
	long value = wcstol(_number, &end, 16);

	CString decStr;
	decStr.Format(L"%d", value);

	return decStr;
}

CString Data::GetFlagSetNotSet(CString _Flag) {
	return (_Flag == L"1") ? L"Set" : L"Not set";
}


CString Data::GetTCPFlagToStr(CString _Flag) {
	CString Result = L"";
	CString Flags[6] = {
		_Flag[0] == L'1' ? L"URG" : L"NULL",
		_Flag[1] == L'1' ? L"ACK" : L"NULL",
		_Flag[2] == L'1' ? L"PSH" : L"NULL",
		_Flag[3] == L'1' ? L"RST" : L"NULL",
		_Flag[4] == L'1' ? L"SYN" : L"NULL",
		_Flag[5] == L'1' ? L"FIN" : L"NULL"
	};

	for (int i = 0; i < 6; i++) {
		if (Flags[i] != L"NULL") {
			if (!Result.IsEmpty()) {
				Result += L", ";
			}
			Result += Flags[i];
		}
	}
	return Result;
}

CString Data::ArpOpcde(CString OpcodeNumber) {
	CString OpcodeStr = L"";
	if (OpcodeNumber.Compare(L"1") == 0) {
		OpcodeStr = "Request";
	}
	else if (OpcodeNumber.Compare(L"2") == 0) {
		OpcodeStr = "Reply";
	}
	return OpcodeStr;
}


CString Data::ArpHardwareType(CString HardwareTypeNumber) {
	CString HardwareTypeStr = L"";
	if (HardwareTypeNumber.Compare(L"1") == 0) {
		HardwareTypeStr = "Ethernet";
	}
	else if (HardwareTypeNumber.Compare(L"2") == 0) {
		HardwareTypeStr = "Experimental Ethernet";
	}
	else if (HardwareTypeNumber.Compare(L"3") == 0) {
		HardwareTypeStr = "Amateur Radio";
	}
	else if (HardwareTypeNumber.Compare(L"4") == 0) {
		HardwareTypeStr = "Proteon ProNet Token Ring";
	}
	else if (HardwareTypeNumber.Compare(L"5") == 0) {
		HardwareTypeStr = "IEEE 802.3 networks";
	}

	return HardwareTypeStr;
}


CString Data::NextHdrType(CString NextHdr) {
	CString NextHdrStr = _T("");
	if (NextHdr.Compare(_T("0")) == 0) {
		NextHdrStr = "IPv6 Hop-by-Hop Option";
	}
	else if (NextHdr.Compare(_T("17")) == 0) {
		NextHdrStr = "UDP";
	}
	else if (NextHdr.Compare(_T("58")) == 0) {
		NextHdrStr = "ICMPv6";
	}
	return NextHdrStr;
}


std::string Data::IcmpMessageTypeStr(pcpp::IcmpMessageType icmptype)
{
	switch (icmptype) {
	case pcpp::IcmpMessageType::ICMP_ECHO_REPLY:
		return "Echo (ping) Reply";
	case pcpp::IcmpMessageType::ICMP_DEST_UNREACHABLE:
		return "Destination Unreachable";
	case pcpp::IcmpMessageType::ICMP_REDIRECT:
		return "Redirection";
	case pcpp::IcmpMessageType::ICMP_ECHO_REQUEST:
		return "Echo (ping) Request";
	case pcpp::IcmpMessageType::ICMP_TIME_EXCEEDED: 
		return "Time Exceeded";
	default:
		return "Etc";
	}
}

std::string Data::Icmpv6MessageTypeStr(pcpp::ICMPv6MessageType icmpv6type)
{
	switch (icmpv6type) {
	case pcpp::ICMPv6MessageType::ICMPv6_DESTINATION_UNREACHABLE:
		return "Destination Unreachable";
	case pcpp::ICMPv6MessageType::ICMPv6_MULTICAST_LISTENER_QUERY:
		return "Multicast Listener Query";
	case pcpp::ICMPv6MessageType::ICMPv6_MULTICAST_LISTENER_REPORT:
		return "Multicast Listener Report";
	case pcpp::ICMPv6MessageType::ICMPv6_ROUTER_SOLICITATION:
		return "Router Solicitation";
	case pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_SOLICITATION:
		return "Neighbor Solicitation";
	case pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_ADVERTISEMENT:
		return "Neighbor Advertisement";
	case pcpp::ICMPv6MessageType::ICMPv6_MULTICAST_LISTENER_DISCOVERY_REPORTS:
		return "Multicast Listener Report Message";
	default:
		return "Etc";
	}
}


CString Data::IcmpDestUnreachableCodes(CString ICMPCode) {
	CString ICMPUnreachableCodeStr = _T("");
	if (ICMPCode.Compare(_T("0")) == 0) {
		ICMPUnreachableCodeStr = "Network Unreachable";
	}
	else if (ICMPCode.Compare(_T("1")) == 0) {
		ICMPUnreachableCodeStr = "Host Unreachable";
	}
	else if (ICMPCode.Compare(_T("2")) == 0) {
		ICMPUnreachableCodeStr = "Protocol Unreachable";
	}
	else if (ICMPCode.Compare(_T("3")) == 0) {
		ICMPUnreachableCodeStr = "Port Unreachable";
	}
	else if (ICMPCode.Compare(_T("4")) == 0) {
		ICMPUnreachableCodeStr = "Time Exceeded";
	}
	else if (ICMPCode.Compare(_T("5")) == 0) {
		ICMPUnreachableCodeStr = "Source Route Failed";
	}
	return ICMPUnreachableCodeStr;
}


CString Data::Icmpv6DestUnreachableCodes(CString ICMPv6Code) {
	CString ICMPUnreachableTypeStr = _T("");
	if (ICMPv6Code.Compare(_T("0")) == 0) {
		ICMPUnreachableTypeStr = "No Route to Destination";
	}
	else if (ICMPv6Code.Compare(_T("3")) == 0) {
		ICMPUnreachableTypeStr = "Address Unreachable";
	}
	else if (ICMPv6Code.Compare(_T("4")) == 0) {
		ICMPUnreachableTypeStr = "Port Unreachable";
	}
	return ICMPUnreachableTypeStr;
}

std::string Data::IgmpTypeStr(pcpp::IgmpType igmptype) {
	switch (igmptype) {
	case pcpp::IgmpType::IgmpType_Unknown:
		return "Unknown";
	case pcpp::IgmpType::IgmpType_MembershipQuery:
		return "Membership Query";
	case pcpp::IgmpType::IgmpType_MembershipReportV1:
		return "Membership Report";
	case pcpp::IgmpType::IgmpType_MembershipReportV2:	/** IGMPv2 Membership Report */
		return "Membership Report";
	case pcpp::IgmpType::IgmpType_LeaveGroup:			/** IGMPv2 Leave Group */
		return "Leave Group";
	case pcpp::IgmpType::IgmpType_MembershipReportV3: /** IGMPv3 Membership Report */
		return "Membership Report";
	default:
		return "Etc";
	}
}


std::string Data::httpMethodToString(pcpp::HttpRequestLayer::HttpMethod method) {
	switch (method) {
	case pcpp::HttpRequestLayer::HttpGET:
		return "GET";
	case pcpp::HttpRequestLayer::HttpPOST:
		return "POST";
	case pcpp::HttpRequestLayer::HttpPUT:
		return "PUT";
	case pcpp::HttpRequestLayer::HttpDELETE:
		return "DELETE";
	case pcpp::HttpRequestLayer::HttpHEAD:
		return "HEAD";
	case pcpp::HttpRequestLayer::HttpOPTIONS:
		return "OPTIONS";
	case pcpp::HttpRequestLayer::HttpTRACE:
		return "TRACE";
	case pcpp::HttpRequestLayer::HttpCONNECT:
		return "CONNECT";
	default:
		return "Etc";
	}
}

std::string Data::httpVersionToString(pcpp::HttpVersion version) {
	switch (version) {
	case pcpp::HttpVersion::ZeroDotNine:
		return "0.9";
	case pcpp::HttpVersion::OneDotZero:
		return "1.0";
	case pcpp::HttpVersion::OneDotOne:
		return "1.1";
	case pcpp::HttpVersion::HttpVersionUnknown:
		return "Etc";
	}
}

std::string Data::httpStatusDescription(pcpp::HttpResponseStatusCode::Value value) {
	switch (value) {
	case pcpp::HttpResponseStatusCode::Http200OK:
		return "OK";
	case pcpp::HttpResponseStatusCode::Http201Created:
		return "Created";
	case pcpp::HttpResponseStatusCode::Http204NoContent:
		return "No Content";
	case pcpp::HttpResponseStatusCode::Http301MovedPermanently:
		return "Moved Permanently";
	case pcpp::HttpResponseStatusCode::Http304NotModified:
		return "Not Modifided";
	case pcpp::HttpResponseStatusCode::Http400BadRequest:
		return "Bad Request";
	case pcpp::HttpResponseStatusCode::Http403Forbidden:
		return "Forbidden";
	case pcpp::HttpResponseStatusCode::Http404NotFound:
		return "Not Found";
	case pcpp::HttpResponseStatusCode::Http408RequestTimeout:
		return "Request Timeout";
	case pcpp::HttpResponseStatusCode::Http500InternalServerError:
		return "Internel Server Error";
	case pcpp::HttpResponseStatusCode::Http503ServiceUnavailable:
		return "Service Unavailable";
	default:
		return "Etc";
	}
}