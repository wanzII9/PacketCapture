#include "Protocol.h"
#include <string>


namespace Data {
	CString DexToBinary(CString _number);
	CString HexToDec(CString _number);

	CString GetTCPFlagToStr(CString _Flag);
	CString GetFlagSetNotSet(CString _Flag);

	CString ArpOpcde(CString OpcodeNumber);
	CString ArpHardwareType(CString HardwareTypeNumber);

	CString NextHdrType(CString NextHdr);

	std::string IcmpMessageTypeStr(pcpp::IcmpMessageType icmptype);
	std::string Icmpv6MessageTypeStr(pcpp::ICMPv6MessageType icmpv6type);
	CString IcmpDestUnreachableCodes(CString ICMPCode);
	CString Icmpv6DestUnreachableCodes(CString ICMPv6Code);

	std::string IgmpTypeStr(pcpp::IgmpType igmptype);

	std::string httpMethodToString(pcpp::HttpRequestLayer::HttpMethod method);
	std::string httpVersionToString(pcpp::HttpVersion version);
	std::string httpStatusDescription(pcpp::HttpResponseStatusCode::Value value);
}