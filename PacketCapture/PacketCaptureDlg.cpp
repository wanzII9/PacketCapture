
// PacketCaptureDlg.cpp: 구현 파일
 // Can depend on _DEBUG or NDEBUG macros

#include "pch.h"
#include "framework.h"
#include "PacketCapture.h"
#include "PacketCaptureDlg.h"
#include "afxdialogex.h"
#include "PcapLiveDeviceList.h"
#include <PcapFileDevice.h>
#include "Protocol.h"
#include <PcapFilter.h>
#include <SystemUtils.h>
#include <fstream>
#include <algorithm>
#include <sstream> 
#include <iomanip>
#include "Data.h"
#include "Filter.h"

#include <winsock.h>
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "iphlpapi.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
//#pragma comment(linker, "/entry:WinMainCRTStartup /subsystem:console")
#define ENABLE_TRACE
#endif


// CPacketCaptureDlg 대화 상자

CPacketCaptureDlg::CPacketCaptureDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PACKETCAPTURE_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPacketCaptureDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_PACKET_LIST, m_PacketCaptureListCtrl);
	DDX_Control(pDX, IDC_PACKET_TREE, m_PacketDataTreeCtrl);
	DDX_Control(pDX, IDC_FILTER_EDIT, m_edit1);
	DDX_Control(pDX, IDC_PACKETDUMP_LIST, m_PacketDumpListCtrl);
	DDX_Control(pDX, IDC_COMBO_NETWORK, m_NetworkComboBox);
	DDX_Control(pDX, IDC_STATIC_PACKETCNT, m_static1);
	DDX_Control(pDX, IDC_STATIC_SELECTEDNET, m_static2);
	DDX_Control(pDX, IDC_STATIC_STATE, m_static3);
}

BEGIN_MESSAGE_MAP(CPacketCaptureDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_START_BUTTON, &CPacketCaptureDlg::OnBnClickedStartButton)
	ON_BN_CLICKED(IDC_STOP_BUTTON, &CPacketCaptureDlg::OnBnClickedStopButton)
	ON_BN_CLICKED(IDC_STOP_BUTTON, &CPacketCaptureDlg::OnBnClickedStopButton)
	ON_MESSAGE(WM_UPDATE_STATS, &CPacketCaptureDlg::OnUpdateUI)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_PACKET_LIST, &CPacketCaptureDlg::OnCustomdrawList)
	ON_NOTIFY(NM_DBLCLK, IDC_PACKET_LIST, &CPacketCaptureDlg::OnNMDblclkList)
	ON_BN_CLICKED(IDC_FILTER_BUTTON, &CPacketCaptureDlg::OnBnClickedFilterButton)
	ON_COMMAND(ID_FILE_SAVE, &CPacketCaptureDlg::OnFileSave)
	ON_COMMAND(ID_FILE_OPEN, &CPacketCaptureDlg::OnFileOpen)
	ON_BN_CLICKED(IDC_NET_SELECT, &CPacketCaptureDlg::OnBnClickedNetSelect)
	ON_UPDATE_COMMAND_UI(ID_FILE_SAVE, &CPacketCaptureDlg::OnUpdateFileSave)
	ON_UPDATE_COMMAND_UI(ID_FILE_OPEN, &CPacketCaptureDlg::OnUpdateFileOpen)
END_MESSAGE_MAP()


// CPacketCaptureDlg 메시지 처리기
BOOL CPacketCaptureDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 이 대화 상자의 아이콘을 설정합니다.  응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.
	GetDlgItem(IDC_STOP_BUTTON)->EnableWindow(FALSE);
	GetDlgItem(IDC_FILTER_BUTTON)->EnableWindow(FALSE);

	// 네트워크 디바이스 목록 가져오기
	int column_count = 1;
	auto deviceList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	for (const auto& dev : deviceList) {
		if (dev->getLinkType() == pcpp::LINKTYPE_ETHERNET) {
			CString device_name(dev->getName().c_str());
			CString device_desc(dev->getDesc().c_str());

			// 콤보박스에 아이템 추가 (네트워크 이름 + 설명)
			CString itemText;
			itemText.Format(_T("%d) %s %s"), column_count, device_desc, device_name);
			m_NetworkComboBox.AddString(itemText);

			m_DeviceList.push_back(dev);

			column_count++;
		}
	}

	if (m_NetworkComboBox.GetCount() == 0) {
		MessageBox(_T("There are no connected network interfaces"), L"Error");
		return -1;
	}

	//PacketCaptureListCtrl
	CRect rectangle;
	m_PacketCaptureListCtrl.GetWindowRect(&rectangle); //ListCtrl의 윈도우 크기 가져옴. 각 열의 너비 계산시 사용
	m_PacketCaptureListCtrl.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);	//그리드 라인 표시, 행 전체 선택할 수 있도록
	LV_COLUMN add_column;	//구조체를 사용해 List Ctrl의 각 열 설정
	add_column.mask = LVCF_TEXT | LVCF_WIDTH;

	const int packet_list_column_count = 8;
	LPWSTR column_name[packet_list_column_count] = { _T("No"), _T("Time"), _T("Source"), _T("Destination"), _T("Protocol"), _T("Length"), _T("Info")};
	double column_width[packet_list_column_count] = { 0.05, 0.15, 0.15, 0.15, 0.07, 0.05, 0.4};	//열 너비의 비율

	for (int i = 0; i < packet_list_column_count - 1; i++) {
		add_column.pszText = column_name[i];	//열의 이름 설정
		add_column.cx = (double)rectangle.Width() * column_width[i]; //열의 너비 설정. rectangle.Width()는 각 열의 너비를 비율로 계산
		m_PacketCaptureListCtrl.InsertColumn(i, &add_column);		// 열을 List Ctrl에 삽입
	}

	//PacketDumpListCtrl
	m_PacketDumpListCtrl.GetWindowRect(&rectangle);
	m_PacketDumpListCtrl.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

	const int packet_dump_column_count = 4;
	LPWSTR packet_dump_header[packet_dump_column_count] = { L"Seq",L"Hex 1",L"HEX 2", L"ASCII" };
	double pakcet_dump_header_width[packet_dump_column_count] = { 0.09,0.33,0.33,0.32 };

	for (int i = 0; i < packet_dump_column_count; i++) {
		add_column.pszText = packet_dump_header[i];
		add_column.cx = rectangle.Width() * pakcet_dump_header_width[i];
		m_PacketDumpListCtrl.InsertColumn(i, &add_column);
	}

	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다.  문서/뷰 모델을 사용하는 MFC 애플리케이션의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CPacketCaptureDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트입니다.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서 이 함수를 호출합니다.
HCURSOR CPacketCaptureDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


// 색상
void CPacketCaptureDlg::OnCustomdrawList(NMHDR * pNMHDR, LRESULT * pResult) {
	LPNMCUSTOMDRAW pNMCD = reinterpret_cast<LPNMCUSTOMDRAW>(pNMHDR);
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	NMLVCUSTOMDRAW* pLVCD = (NMLVCUSTOMDRAW*)pNMHDR;

	if (CDDS_PREPAINT == pLVCD->nmcd.dwDrawStage) {
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (CDDS_ITEMPREPAINT == pLVCD->nmcd.dwDrawStage) {
		CString Protocol = m_PacketCaptureListCtrl.GetItemText(pLVCD->nmcd.dwItemSpec, 4);
		CString Info = m_PacketCaptureListCtrl.GetItemText(pLVCD->nmcd.dwItemSpec, 6);

		if (Protocol == _T("TCP") || Protocol == _T("SSH") || (Protocol == _T("FTP")) || (Protocol == _T("Telnet")) || (Protocol == _T("TLS"))) {
			pLVCD->clrTextBk = RGB(231, 230, 255);
		}
		else if (Protocol == _T("UDP") || (Protocol == _T("DHCP")) || (Protocol == _T("DNS"))) {
			pLVCD->clrTextBk = RGB(218, 238, 255);
		}
		else if (Protocol == _T("ICMP") || (Protocol == _T("ICMPv6"))) {
			pLVCD->clrTextBk = RGB(252, 224, 255);
		}
		else if (Protocol == _T("ARP")) {
			pLVCD->clrTextBk = RGB(250, 240, 215);
		}
		else if (Protocol == _T("HTTP")) {
			pLVCD->clrTextBk = RGB(228, 255, 199);
		}
		else if (Protocol == _T("IGMP") || (Protocol == _T("IGMPv2")) || (Protocol == _T("IGMPv3"))) {
			pLVCD->clrTextBk = RGB(255, 243, 214);
		}
		*pResult = CDRF_DODEFAULT;
	}
}

void CPacketCaptureDlg::SelectedNetworkInterfaceInfo() {
	CString strText;
	strText.Format(L"%s is selected", m_SelectedDeviceDesc);
	SetDlgItemText(IDC_STATIC_STATE, strText);
	SetDlgItemText(IDC_STATIC_SELECTEDNET, m_SelectedDeviceDesc);
}


void CPacketCaptureDlg::OnNMDblclkList(NMHDR* pNMHDR, LRESULT* pResult) {
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	*pResult = 0;

	//클릭된 항목이 유효한 경우(pNMItemActivate->iItem != -1) 다음 작업을 수행
	if (pNMItemActivate->iItem != -1) {
		CString FrameNumber = m_PacketCaptureListCtrl.GetItemText(pNMItemActivate->iItem, 0);
		CString Time = m_PacketCaptureListCtrl.GetItemText(pNMItemActivate->iItem, 1);
		CString Source = m_PacketCaptureListCtrl.GetItemText(pNMItemActivate->iItem, 2);
		CString Destination = m_PacketCaptureListCtrl.GetItemText(pNMItemActivate->iItem, 3);
		CString Protocol = m_PacketCaptureListCtrl.GetItemText(pNMItemActivate->iItem, 4);
		CString Length = m_PacketCaptureListCtrl.GetItemText(pNMItemActivate->iItem, 5);
		CString Info = m_PacketCaptureListCtrl.GetItemText(pNMItemActivate->iItem, 6);


		if(PrevClickColumnNumber != _ttoi(FrameNumber)) {
			m_PacketDataTreeCtrl.DeleteAllItems();
			m_PacketDumpListCtrl.DeleteAllItems();

			// 파일에서 패킷 데이터를 읽어오기
			std::ifstream inFile("captured_packets.dat", std::ios::binary);
			if (!inFile.is_open()) {
				AfxMessageBox(_T("Error opening captured_packets.dat for reading."));
				return;
			}

			int index = 0;

			while (true) {
				uint32_t dataLen = 0;
				inFile.read(reinterpret_cast<char*>(&dataLen), sizeof(dataLen));

				if (inFile.eof() || dataLen == 0) {
					break;
				}

				std::vector<uint8_t> buffer(dataLen);
				inFile.read(reinterpret_cast<char*>(buffer.data()), dataLen);

				// 타임스탬프 읽기
				time_t sec;
				long nsec;
				inFile.read(reinterpret_cast<char*>(&sec), sizeof(sec));
				inFile.read(reinterpret_cast<char*>(&nsec), sizeof(nsec));

				timespec timestamp;
				timestamp.tv_sec = sec;
				timestamp.tv_nsec = nsec;

				if (index == pNMItemActivate->iItem) {
					pcpp::RawPacket rawPacket(buffer.data(), dataLen, timestamp, false);
					pcpp::Packet parsedPacket(&rawPacket);

					std::string packet_dump_data_string;
					for (int i = 1; (i < parsedPacket.getRawPacket()->getRawDataLen() + 1); i++) {
						int temp = parsedPacket.getRawPacket()->getRawData()[i - 1];
						std::stringstream stream;
						stream << std::setw(2) << std::setfill('0') << std::hex << temp;
						packet_dump_data_string += stream.str();
					}

					CString Packet_Dump_Data(packet_dump_data_string.c_str());

					// 새로운 데이터로 패킷 데이터를 설정
					PacketDetail(parsedPacket.getRawPacket(), FrameNumber, Time, Source, Destination, Protocol, Length);

					//HDX 에디터에 패킷 덤프 데이터를 설정
					SetDataToHDXEditor(Packet_Dump_Data);
					break;
				}

				index++;
			}

			inFile.close();

			// 현재 클릭된 항목 번호를 PrevClickColumnNumber에 저장
			PrevClickColumnNumber = _ttoi(FrameNumber);
		}
	}
}


//메시지 큐에서 WM_UPDATE_STATS 메시지를 처리할 때 호출되는 함수
//큐에서 패킷 정보(packetinfo 구조체)를 가져와서 리스트 컨트롤에 추가
LRESULT CPacketCaptureDlg::OnUpdateUI(WPARAM wParam, LPARAM lParam)
{
	ChangePktCountText();

	PacketInfo packetinfo;
	//packetQueue에 대한 액세스를 동기화
	{
		std::lock_guard<std::mutex> lock(queueMutex);
		if (!packetQueue.empty()) {
			packetinfo = packetQueue.front();			// 큐의 가장 앞에 있는 패킷 정보를 packetinfo 구조체에 저장
			packetQueue.pop();
		}
		else {
			return 0;									// 큐가 비어있으면 아무 작업도 하지 않음
		}
	}

	int column_count = m_PacketCaptureListCtrl.GetItemCount();
	CString column_count_str;
	column_count_str.Format(_T("%d"), column_count + 1);
	m_PacketCaptureListCtrl.InsertItem(column_count, column_count_str);
	m_PacketCaptureListCtrl.SetItemText(column_count, 1, packetinfo.PacketTimeStr);
	m_PacketCaptureListCtrl.SetItemText(column_count, 2, packetinfo.SrcIP);
	m_PacketCaptureListCtrl.SetItemText(column_count, 3, packetinfo.DstIP);
	m_PacketCaptureListCtrl.SetItemText(column_count, 4, packetinfo.Protocol);
	m_PacketCaptureListCtrl.SetItemText(column_count, 5, packetinfo.Length);
	m_PacketCaptureListCtrl.SetItemText(column_count, 6, packetinfo.Info);

	if (CursorPositionLast) {
		m_PacketCaptureListCtrl.EnsureVisible(column_count, FALSE);
	}

	return 0;
}


void CPacketCaptureDlg::onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	CPacketCaptureDlg* dlg = static_cast<CPacketCaptureDlg*>(cookie);
	pcpp::Packet parsedPacket(packet);		// parsed the raw packet

	dlg->stats.consumePacket(parsedPacket);

	if (dlg->m_pFilter && !dlg->m_pFilter->matchPacketWithFilter(packet))	// 필터와 일치하지 않으면 패킷을 무시
	{
		return;
	}

	// 각 패킷의 정보를 저장하기 위한 일회용 객체. 
	//onPacketArrives 함수가 호출될 때마다 packetinfo 구조체가 새로 생성되고, 이 구조체에 패킷의 정보 저장
	PacketInfo packetinfo;

	//패킷의 time 정보 추출
	timespec packetTimestamp = packet->getPacketTimeStamp();
	SYSTEMTIME st;
	GetLocalTime(&st);
	
	//시간 정보 저장
	packetinfo.PacketTimeStr.Format(_T("%02d-%02d-%02d %02d:%02d:%02d.%03d"), st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
		packetTimestamp.tv_sec % 60, (int)packetTimestamp.tv_nsec / 100000);
	//길이
	packetinfo.Length.Format(_T("%u"), packet->getRawDataLen());

	std::ofstream outFile("captured_packets.dat", std::ios::binary | std::ios::app);
	if (outFile.is_open())
	{
		uint32_t dataLen = packet->getRawDataLen();
		outFile.write(reinterpret_cast<const char*>(&dataLen), sizeof(dataLen));
		outFile.write(reinterpret_cast<const char*>(packet->getRawData()), dataLen);

		// 타임스탬프를 저장합니다.
		outFile.write(reinterpret_cast<const char*>(&packetTimestamp.tv_sec), sizeof(packetTimestamp.tv_sec));
		outFile.write(reinterpret_cast<const char*>(&packetTimestamp.tv_nsec), sizeof(packetTimestamp.tv_nsec));

		outFile.close();
	}
	
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

		goto UIUpdate;
	}

	if (parsedPacket.isPacketOfType(pcpp::ICMP))
	{
		packetinfo.Protocol = _T("ICMP");
		std::string ICMPTypeStr = Data::IcmpMessageTypeStr(parsedPacket.getLayerOfType<pcpp::IcmpLayer>()->getMessageType());
		packetinfo.Info.Format(_T("%S"), ICMPTypeStr.c_str());

		goto UIUpdate;
	}

	else if (parsedPacket.isPacketOfType(pcpp::ICMPv6))
	{
		packetinfo.Protocol = _T("ICMPv6");
		std::string ICMPv6TypeStr = Data::Icmpv6MessageTypeStr(parsedPacket.getLayerOfType <pcpp::IcmpV6Layer>()->getMessageType());
		packetinfo.Info.Format(_T("%S"), ICMPv6TypeStr.c_str());

		goto UIUpdate;
	}

	else if (parsedPacket.isPacketOfType(pcpp::IGMPv3))
	{
		std::string IGMPTypeStr = Data::IgmpTypeStr(parsedPacket.getLayerOfType<pcpp::IgmpLayer>()->getType());

		CString IGMPTypeStrCString(IGMPTypeStr.c_str());
		packetinfo.Info.Format(_T("%s"), IGMPTypeStrCString);
		packetinfo.Protocol = _T("IGMPv3");
		goto UIUpdate;
	}

	else if (parsedPacket.isPacketOfType(pcpp::IGMPv2))
	{
		std::string IGMPTypeStr = Data::IgmpTypeStr(parsedPacket.getLayerOfType<pcpp::IgmpLayer>()->getType());

		CString IGMPTypeStrCString(IGMPTypeStr.c_str());
		packetinfo.Info.Format(_T("%s"), IGMPTypeStrCString);
		packetinfo.Protocol = _T("IGMPv2");
		goto UIUpdate;
	}

	else if (parsedPacket.isPacketOfType(pcpp::IGMP))
	{
		std::string IGMPTypeStr = Data::IgmpTypeStr(parsedPacket.getLayerOfType<pcpp::IgmpLayer>()->getType());

		CString IGMPTypeStrCString(IGMPTypeStr.c_str());
		packetinfo.Info.Format(_T("%s"), IGMPTypeStrCString);
		packetinfo.Protocol = _T("IGMP");

		goto UIUpdate;
	}

	else if (parsedPacket.isPacketOfType(pcpp::TCP))
	{
		packetinfo.Info.Format(_T("%u -> %u"), ntohs(parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portSrc),
			ntohs(parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portDst));

		if (parsedPacket.getLastLayer() == parsedPacket.getLayerOfType<pcpp::TcpLayer>())
		{
			packetinfo.Protocol = _T("TCP");
			goto UIUpdate;
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
				goto UIUpdate;
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
				goto UIUpdate;
			}
		}//HTTP

		else if (parsedPacket.isPacketOfType(pcpp::FTP))
		{
			packetinfo.Protocol = _T("FTP");
			goto UIUpdate;
		}

		else if (parsedPacket.isPacketOfType(pcpp::SSH))
		{
			packetinfo.Protocol = _T("SSH");
			goto UIUpdate;
		}

		else if (parsedPacket.isPacketOfType(pcpp::Telnet))
		{
			packetinfo.Protocol = _T("Telnet");
			goto UIUpdate;
		}

		else if (parsedPacket.isPacketOfType(pcpp::SSL))
		{
			packetinfo.Protocol = _T("TLS");
			goto UIUpdate;
		}
		else {
			packetinfo.Protocol = _T("TCP");
			goto UIUpdate;
		}
	}//TCP

	else if (parsedPacket.isPacketOfType(pcpp::UDP))
	{
		packetinfo.Info.Format(_T("%u -> %u"), ntohs(parsedPacket.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portSrc),
												ntohs(parsedPacket.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portDst));

		if (parsedPacket.getLastLayer() == parsedPacket.getLayerOfType<pcpp::PayloadLayer>())
		{
			packetinfo.Protocol = _T("UDP");
			goto UIUpdate;
		}

		else if (parsedPacket.isPacketOfType(pcpp::DHCP))
		{
			packetinfo.Protocol = _T("DHCP");
			goto UIUpdate;
		}

		else if (parsedPacket.isPacketOfType(pcpp::DNS))
		{
			packetinfo.Protocol = _T("DNS");
			goto UIUpdate;
		}
		else {
			packetinfo.Protocol = _T("UDP");
			goto UIUpdate;
		}

	}

	else
	{
		packetinfo.Protocol = _T("Unknown");
	}

	UIUpdate:
		if (dlg->m_PacketCaptureListCtrl.GetItemCount() == 0) {

			std::string packet_dump_data_string;											//패킷 데이터를 16진수 문자열로 저장하기 위한 string 객체 선언
			for (int i = 1; (i < parsedPacket.getRawPacket()->getRawDataLen() + 1); i++) 
			{	//패킷의 모든 바이트를 순차적으로 처리
				int temp = parsedPacket.getRawPacket()->getRawData()[i - 1];				//현재 바이트의 값을 가져와서 temp에 저장
				std::stringstream stream;													//숫자를 16진수 문자열로 변환하기 위해 std::stringstream 객체 생성
				stream << std::setw(2) << std::setfill('0') << std::hex << temp;			//temp 값이 16진수 문자열로 변환되어 스트림에 추가

				packet_dump_data_string += stream.str();									//변환된 16진수 문자열을 packet_dump_data_string에 추가
				//패킷의 각 바이트를 16진수로 변환하여 하나의 긴 문자열로 연결
			}
			CString packet_dump_data_cstr(packet_dump_data_string.c_str());

			CString column_count_str = L"1";
			dlg->PacketDetail(packet, column_count_str, packetinfo.PacketTimeStr, packetinfo.SrcIP, packetinfo.DstIP,
				packetinfo.Protocol, (CString)(std::to_string(parsedPacket.getRawPacket()->getRawDataLen()).c_str()));

			dlg->SetDataToHDXEditor(packet_dump_data_cstr);
		}

		std::lock_guard<std::mutex> lock(dlg->queueMutex);
		dlg->packetQueue.push(packetinfo);
		::PostMessage(dlg->GetSafeHwnd(), WM_UPDATE_STATS, 0, 0);
}


void CPacketCaptureDlg::PacketDetail(pcpp::RawPacket* packet, CString FrameNumber, CString Time, CString Source,
	CString Destination, CString Protocol, CString Length)
{
	//초기 설정
	HTREEITEM  PacketDataRoot1 = nullptr;
	HTREEITEM  PacketDataRoot2 = nullptr;
	HTREEITEM  PacketDataRoot3 = nullptr;
	HTREEITEM  PacketDataRoot4 = nullptr;
	HTREEITEM  PacketDataRoot5 = nullptr;

	m_PacketDataTreeCtrl.DeleteAllItems();
	m_PacketDataTreeCtrl.Invalidate();		//화면 전체를 재표시

	CString PacketDataLine1;	//Frame
	CString PacketDataLine2;	//Ethernet II
	CString PacketDataLine3;	//IPv4
	CString PacketDataLine4;	//TCP, UDP, ARP, ICMP

	// Line 1 정보 입력
	PacketDataLine1 = L"Frame " + FrameNumber + L": "
		+ Length + L"bytes on wire (" + CString(std::to_string(_ttoi(Length) * 8).c_str()) + L" bits), "
		+ Length + L"bytes captured (" + CString(std::to_string(_ttoi(Length) * 8).c_str()) + L" bits) on interface 0";


	CString PakcetDataLine1by1 = L"Interface id: 0 (" + m_SelectedDeviceName + L")";
	CString PakcetDataLine1by1by1 = L"Interface name: " + m_SelectedDeviceName;
	CString PakcetDataLine1by1by2 = L"Interface desciption: " + m_SelectedDeviceDesc;

	CString PakcetDataLine1by2 = L"Encapsulation type: Ethernet (1)";
	CString PakcetDataLine1by3 = L"Arrival Time: " + Time;
	CString PakcetDataLine1by4 = L"Frame Number: " + FrameNumber;
	CString PakcetDataLine1by5 = L"Frame Length: " + Length + L" bytes (" + CString(std::to_string(_ttoi(Length) * 8).c_str()) + L" bits)";
	CString PakcetDataLine1by6 = L"Capture Length: " + Length + L" bytes (" + CString(std::to_string(_ttoi(Length) * 8).c_str()) + L" bits)";

	// Line 2 정보 입력
	pcpp::Packet parsedPacket(packet);
	CString Source_addr = CString(parsedPacket.getLayerOfType<pcpp::EthLayer>()->getSourceMac().toString().c_str());
	CString Destination_addr = CString(parsedPacket.getLayerOfType<pcpp::EthLayer>()->getDestMac().toString().c_str());

	PacketDataLine2 = L"Ethernet ⅠⅠ, Src: " + Source_addr + L", Dst: " + Destination_addr;
	CString PakcetDataLine2by1 = L"Destination: " + Destination_addr;
	CString PakcetDataLine2by2 = L"Source: " + Source_addr;

	CString Type;
	Type.Format(_T("%04X"), pcpp::netToHost16(parsedPacket.getLayerOfType<pcpp::EthLayer>()->getEthHeader()->etherType));	//4자리 16진수. 앞 빈자리는 0

	CString TypeName;
	CString Icmpv6TypeName;
	if (Type == _T("0800")) {
		TypeName = _T("IPv4");
	}
	else if (Type == _T("0806")) {
		TypeName = _T("ARP");
	}
	else if (Type == _T("86DD")) {
		TypeName = _T("IPv6");
		Icmpv6TypeName = _T("v6");
	}

	CString PakcetDataLine2by3 = _T("Type: ") + TypeName + _T(" (0x") + Type + _T(")");

	//출력
	// Line 1 Frame 출력
	PacketDataRoot1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine1);
	HTREEITEM PacketDataRoot1Child1 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by1, PacketDataRoot1);
	HTREEITEM PacketDataRoot1Child1Child1 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by1by1, PacketDataRoot1Child1);
	HTREEITEM PacketDataRoot1Child1Child2 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by1by2, PacketDataRoot1Child1);

	HTREEITEM PacketDataRoot1Child2 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by2, PacketDataRoot1);
	HTREEITEM PacketDataRoot1Child3 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by3, PacketDataRoot1);
	HTREEITEM PacketDataRoot1Child4 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by4, PacketDataRoot1);
	HTREEITEM PacketDataRoot1Child5 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by5, PacketDataRoot1);
	HTREEITEM PacketDataRoot1Child6 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by6, PacketDataRoot1);
	 
	// Line 2 Ethernet 출력
	PacketDataRoot2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine2);
	HTREEITEM PacketDataRoot2Child1 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine2by1, PacketDataRoot2);
	HTREEITEM PacketDataRoot2Child2 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine2by2, PacketDataRoot2);
	HTREEITEM PacketDataRoot2Child3 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine2by3, PacketDataRoot2);


	//Line3 IPv4, IPv6, ARP
	if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
		pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

		CString ipVersionStr; //4 출력
		ipVersionStr.Format(_T("%u"), ipv4Layer->getIPv4Header()->ipVersion);

		CString headerLengthStr; //5 출력
		headerLengthStr.Format(_T("%u"), ipv4Layer->getIPv4Header()->internetHeaderLength);

		CString typeOfService;
		typeOfService.Format(_T("%02X"), pcpp::netToHost16(ipv4Layer->getIPv4Header()->typeOfService));

		CString totalLengthstr;
		totalLengthstr.Format(_T("%u"), pcpp::netToHost16(ipv4Layer->getIPv4Header()->totalLength));


		CString Identification;
		Identification.Format(_T("%04X"), pcpp::netToHost16(ipv4Layer->getIPv4Header()->ipId));

		CString timeToLive;
		timeToLive.Format(_T("%u"), ipv4Layer->getIPv4Header()->timeToLive);

		CString headerChecksum;
		headerChecksum.Format(_T("%04X"), pcpp::netToHost16(ipv4Layer->getIPv4Header()->headerChecksum));

		CString protocolnum;
		protocolnum.Format(_T("%u"), ipv4Layer->getIPv4Header()->protocol);

		CString ipVersionBinary = Data::DexToBinary(ipVersionStr);
		CString headerLengthBinary = Data::DexToBinary(headerLengthStr);
		CString IdentificationDec = Data::HexToDec(Identification);

		PacketDataLine3 = L"Internet Protocol Version " + ipVersionStr + L", Src: " + Source + L", Dst: " + Destination;
		CString PacketDataLine3by1 = ipVersionBinary + L"  . . . . = Version: " + ipVersionStr;
		CString PacketDataLine3by2 = L". . . .  " + headerLengthBinary + " = Header Length: " + CString(std::to_string((_ttoi(headerLengthStr) * 4)).c_str()) + L" bytes (" + headerLengthStr + L")";
		CString PacketDataLine3by3 = L"Differentinated Services Field: 0x" + typeOfService;
		CString PacketDataLine3by4 = L"Total Length: " + totalLengthstr;
		CString PacketDataLine3by5 = L"Identification: 0x" + Identification + L" (" + IdentificationDec + L")";
		CString PacketDataLine3by6 = L"Time to live: " + timeToLive;
		CString PacketDataLine3by7 = L"Protocol: " + Protocol + L"(" + protocolnum + L")";
		CString PacketDataLine3by8 = _T("Header checksum: 0x") + headerChecksum;
		CString PacketDataLine3by9 = L"Source: " + Source;
		CString PacketDataLine3by10 = L"Destination: " + Destination;

		//Line 3 IPv4 출력
		PacketDataRoot3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3);
		HTREEITEM PacketDataRoot3Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by1, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by2, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by3, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by4, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by5, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child6 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by6, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child7 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by7, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child8 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by8, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child9 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by9, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child10 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by10, PacketDataRoot3);
	}

	else if (parsedPacket.isPacketOfType(pcpp::IPv6)) {
		pcpp::ip6_hdr* ip6Header = parsedPacket.getLayerOfType<pcpp::IPv6Layer>()->getIPv6Header();

		CString ip6VersionStr;
		ip6VersionStr.Format(_T("%u"), ip6Header->ipVersion); //ipversion 상위4비트

		CString TrafficClass;
		TrafficClass.Format(_T("%02X"), pcpp::netToHost16(ip6Header->trafficClass));

		uint32_t flowLabelValue = (ip6Header->flowLabel[0] << 16) |
			(ip6Header->flowLabel[1] << 8) |
			ip6Header->flowLabel[2];

		CString FlowLabel;
		FlowLabel.Format(_T("%05X"), flowLabelValue);

		CString PayloadLength;
		PayloadLength.Format(_T("%u"), pcpp::netToHost16(ip6Header->payloadLength));

		CString NextHdr;
		NextHdr.Format(_T("%u"), ip6Header->nextHeader);

		CString NextHdrStr = Data::NextHdrType(NextHdr);

		CString HopLimit;
		HopLimit.Format(_T("%u"), ip6Header->hopLimit);

		CString ipVersionBinary = Data::DexToBinary(ip6VersionStr);

		PacketDataLine3 = _T("Internet Protocol Version ") + ip6VersionStr + _T(", Src: ") + Source + _T(", Dst: ") + Destination;
		CString PacketDataLine3by1 = ipVersionBinary + _T("  . . . . = Version: ") + ip6VersionStr;
		CString PacketDataLine3by2 = _T("Traffic Class: 0x") + TrafficClass;
		CString PacketDataLine3by3 = _T("Flow Label: 0x") + FlowLabel;
		CString PacketDataLine3by4 = _T("Payload Length: ") + PayloadLength;
		CString PacketDataLine3by5 = _T("Next Header: ") + NextHdrStr + _T(" (") + NextHdr + _T(")");
		CString PacketDataLine3by6 = _T("Hop Limit: ") + HopLimit;
		CString PacketDataLine3by7 = _T("Source Address: ") + Source;
		CString PacketDataLine3by8 = _T("Destination Address: ") + Destination;

		//Line 3 IPv6 출력
		PacketDataRoot3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3);
		HTREEITEM PacketDataRoot3Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by1, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by2, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by3, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by4, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by5, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child6 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by6, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child7 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by7, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child8 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by8, PacketDataRoot3);
	}

	else if (parsedPacket.isPacketOfType(pcpp::ARP)) {
		pcpp::ArpLayer* arpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();

		PacketDataLine3 = L"Address Resolution Protocol";

		CString HardwareTypeNumber;
		HardwareTypeNumber.Format(_T("%u"), pcpp::netToHost16(arpLayer->getArpHeader()->hardwareType));

		CString HardwareTypeStr = Data::ArpHardwareType(HardwareTypeNumber);

		CString ProtocolType;
		ProtocolType.Format(_T("%04X"), pcpp::netToHost16(arpLayer->getArpHeader()->protocolType));

		CString HardwareSize;
		HardwareSize.Format(_T("%u"), arpLayer->getArpHeader()->hardwareSize);

		CString ProtocolSize;
		ProtocolSize.Format(_T("%u"), arpLayer->getArpHeader()->protocolSize);

		CString OpCodeNumber;
		OpCodeNumber.Format(_T("%u"), pcpp::netToHost16(arpLayer->getArpHeader()->opcode));

		CString OpCodeStr = Data::ArpOpcde(OpCodeNumber);

		CString PacketDataLine3by1 = L"Hardware type: " + HardwareTypeStr + L" (" + HardwareTypeNumber + L")";
		CString PacketDataLine3by2 = L"Protocol type: IPv4 (0x" + ProtocolType + L")";
		CString PacketDataLine3by3 = L"Hardware size: " + HardwareSize;
		CString PacketDataLine3by4 = L"Protocol size: " + ProtocolSize;
		CString PacketDataLine3by5 = L"Opcode: " + OpCodeStr + L" (" + OpCodeNumber + L")";
		CString PacketDataLine3by6 = L"Sender MAC address: " + CString(arpLayer->getSenderMacAddress().toString().c_str());
		CString PacketDataLine3by7 = L"Sender IP address: " + CString(arpLayer->getSenderIpAddr().toString().c_str());
		CString PacketDataLine3by8 = L"Target MAC address: " + CString(arpLayer->getTargetMacAddress().toString().c_str());
		CString PacketDataLine3by9 = L"Target IP address: " + CString(arpLayer->getTargetIpAddr().toString().c_str());

		PacketDataRoot3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3);
		HTREEITEM PacketDataRoot3Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by1, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by2, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by3, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by4, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by5, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child6 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by6, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child7 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by7, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child8 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by8, PacketDataRoot3);
		HTREEITEM PacketDataRoot3Child9 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by9, PacketDataRoot3);

		goto UpdatePacketInfo;
		}

	if (Protocol == _T("ICMP")) {
		PacketDataLine4 = L"Ineternet Control Message Protocol";

		pcpp::IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
		CString ICMPType;
		ICMPType.Format(_T("%u"), icmpLayer->getMessageType());

		std::string ICMPTypeStr = Data::IcmpMessageTypeStr(parsedPacket.getLayerOfType<pcpp::IcmpLayer>()->getMessageType());
		CString ICMPTypeCString(ICMPTypeStr.c_str());

		pcpp::icmphdr* icmpHdr = parsedPacket.getLayerOfType<pcpp::IcmpLayer>()->getIcmpHeader();
		CString ICMPCode;
		ICMPCode.Format(_T("%u"), icmpHdr->code);

		CString ICMPChecksum;
		ICMPChecksum.Format(_T("%04X"), pcpp::netToHost16((icmpHdr->checksum)));

		CString PacketDataLine4by1 = _T("Type: ") + ICMPType + _T(" (") + ICMPTypeCString + _T(")");

		if (ICMPType == 3) {
			CString ICMPUnreachableCodeStr = Data::IcmpDestUnreachableCodes(ICMPCode);
			CString PacketDataLine4by2 = _T("Code: ") + ICMPCode + _T("(") + ICMPUnreachableCodeStr + _T(")");
		}

		CString PacketDataLine4by2 = _T("Code: ") + ICMPCode;
		CString PacketDataLine4by3 = _T("Checksum: 0x") + ICMPChecksum;


		PacketDataRoot4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4);
		HTREEITEM PacketDataRoot4Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by1, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by2, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by3, PacketDataRoot4);

		if ((icmpHdr->type == 8) || (icmpHdr->type == 0)) {
			pcpp::icmp_echo_hdr* echoHeader = (pcpp::icmp_echo_hdr*)icmpHdr;
			pcpp::icmp_echo_request* echoData = nullptr;

			if (icmpHdr->type == 8)
				echoData = (pcpp::icmp_echo_request*)icmpLayer->getEchoRequestData();
			else if (icmpHdr->type == 0)
				echoData = (pcpp::icmp_echo_reply*)icmpLayer->getEchoReplyData();

			CString ICMPEchoDataLength;
			ICMPEchoDataLength.Format(_T("%zu"), echoData->dataLength - 8);

			CString ICMPIdentifierBEDec;
			ICMPIdentifierBEDec.Format(_T("%u"), pcpp::netToHost16(echoHeader->id));


			CString ICMPIdentifierBEHex;
			ICMPIdentifierBEHex.Format(_T("%04X"), pcpp::netToHost16(echoHeader->id));

			CString ICMPIdentifierLEDec;
			ICMPIdentifierLEDec.Format(_T("%u"), echoHeader->id);

			CString ICMPIdentifierLEHex;
			ICMPIdentifierLEHex.Format(_T("%04X"), echoHeader->id);

			CString ICMPSquenceNumberBEDec;
			ICMPSquenceNumberBEDec.Format(_T("%u"), pcpp::netToHost16(echoHeader->sequence));

			CString ICMPSquenceNumberBEHex;
			ICMPSquenceNumberBEHex.Format(_T("%04X"), pcpp::netToHost16(echoHeader->sequence));

			CString ICMPSquenceNumberLEDec;
			ICMPSquenceNumberLEDec.Format(_T("%u"), echoHeader->sequence);

			CString ICMPSquenceNumberLEHex;
			ICMPSquenceNumberLEHex.Format(_T("%04X"), echoHeader->sequence);

			CString PacketDataLine4by4 = _T("Identifier (BE): ") + ICMPIdentifierBEDec + _T(" (0x") + ICMPIdentifierBEHex + _T(")");
			CString PacketDataLine4by5 = _T("Identifier (LE): ") + ICMPIdentifierLEDec + _T(" (0x") + ICMPIdentifierLEHex + _T(")");
			CString PacketDataLine4by6 = _T("Sequence number (BE): ") + ICMPSquenceNumberBEDec + _T(" (0x") + ICMPSquenceNumberBEHex + _T(")");
			CString PacketDataLine4by7 = _T("Sequence number (LE): ") + ICMPSquenceNumberLEDec + _T(" (0x") + ICMPSquenceNumberLEHex + _T(")");
			CString PacketDataLine4by8 = _T("Data (") + ICMPEchoDataLength + _T(" bytes )");

			HTREEITEM PacketDataRoot4Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by4, PacketDataRoot4);
			HTREEITEM PacketDataRoot4Child5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by5, PacketDataRoot4);
			HTREEITEM PacketDataRoot4Child6 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6, PacketDataRoot4);
			HTREEITEM PacketDataRoot4Child7 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by7, PacketDataRoot4);
			HTREEITEM PacketDataRoot4Child8 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by8, PacketDataRoot4);
		}
		goto UpdatePacketInfo;
	}

	else if (Protocol == L"ICMPv6") {
		PacketDataLine4 = _T("Ineternet Control Message Protocol ") + Icmpv6TypeName;

		CString ICMPv6Type;
		ICMPv6Type.Format(_T("%u"), parsedPacket.getLayerOfType<pcpp::IcmpV6Layer>()->getMessageType());

		std::string ICMPv6TypeStr = Data::Icmpv6MessageTypeStr(parsedPacket.getLayerOfType<pcpp::IcmpV6Layer>()->getMessageType());
		CString ICMPv6TypeCString(ICMPv6TypeStr.c_str());


		CString ICMPv6Code;
		ICMPv6Code.Format(_T("%u"), parsedPacket.getLayerOfType<pcpp::IcmpV6Layer>()->getCode());

		CString ICMPv6Checksum;
		ICMPv6Checksum.Format(_T("%04X"), parsedPacket.getLayerOfType<pcpp::IcmpV6Layer>()->getChecksum());

		CString PacketDataLine4by1 = _T("Type: ") + ICMPv6TypeCString + _T(" (") + ICMPv6Type + _T(")");

		CString PacketDataLine4by3 = _T("Checksum: 0x") + ICMPv6Checksum;

		PacketDataRoot4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4);
		HTREEITEM PacketDataRoot4Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by1, PacketDataRoot4);

		if (ICMPv6Type == 1) {
			CString ICMPv6UnreachableTypeStr = Data::Icmpv6DestUnreachableCodes(ICMPv6Code);
			CString PacketDataLine4by2 = _T("Code: ") + ICMPv6Code + _T("(") + ICMPv6UnreachableTypeStr + _T(")");
			HTREEITEM PacketDataRoot4Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by2, PacketDataRoot4);
		}
		else {
			CString PacketDataLine4by2 = _T("Code: ") + ICMPv6Code;
			HTREEITEM PacketDataRoot4Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by2, PacketDataRoot4);
		}

		HTREEITEM PacketDataRoot4Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by3, PacketDataRoot4);
		goto UpdatePacketInfo;
	}

	else if (Protocol == _T("IGMP") || Protocol == _T("IGMPv2") || Protocol == _T("IGMPv3")) {
		pcpp::IgmpLayer* igmpLayer = parsedPacket.getLayerOfType<pcpp::IgmpLayer>();
		PacketDataLine4 = _T("Internet Group Management Protocol ");

		CString IGMPType;
		IGMPType.Format(_T("%02X"), igmpLayer->getType());

		std::string IGMPTypeStrStd = Data::IgmpTypeStr(igmpLayer->getType()); // std::string
		CString IGMPTypeStr = CString(IGMPTypeStrStd.c_str());

		CString PacketDataLine4by1 = _T("[") + Protocol + _T("]");
		CString PacketDataLine4by2 = _T("Type: ") + IGMPTypeStr + _T(" (0x") + IGMPType + _T(")");

		PacketDataRoot4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4);
		HTREEITEM PacketDataRoot4Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by1, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by2, PacketDataRoot4);
		goto UpdatePacketInfo;
	}

	//Line4 입력 TCP
	else if ((Protocol == _T("TCP")) || Protocol == _T("HTTP") || Protocol == _T("FTP")
		|| Protocol == _T("SSH") || Protocol == _T("Telnet") || Protocol == _T("TLS")) {

		pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();

		CString TcpSrcPort;
		TcpSrcPort.Format(_T("%u"), tcpLayer->getSrcPort());

		CString TcpDstPort;
		TcpDstPort.Format(_T("%u"), tcpLayer->getDstPort());

		CString seqnum;
		uint32_t seq = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);
		seqnum.Format(_T("%llu"), static_cast<unsigned long long>(seq));

		CString acknum;
		uint32_t ack = ntohl(tcpLayer->getTcpHeader()->ackNumber);
		acknum.Format(_T("%llu"), static_cast<unsigned long long>(ack));

		CString tcpheaderlen;	//5
		tcpheaderlen.Format(_T("%u"), static_cast<unsigned int>(tcpLayer->getHeaderLen() / 4));

		PacketDataLine4 = L"Transmission Control Protocol, Src Port: " + TcpSrcPort + L", Dst Port: " + TcpDstPort;
		CString PacketDataLine4by1 = L"Source Port: " + TcpSrcPort;
		CString PacketDataLine4by2 = L"Destination Port: " + TcpDstPort;

		CString PacketDataLine4by3 = L"Sequence number (raw): " + seqnum;
		CString PacketDataLine4by4 = L"Acknowledge number (raw): " + acknum;

		CString PacketDataLine4by5 = Data::DexToBinary(tcpheaderlen) + L" . . . . = Header Length: "
			+ CString(std::to_string(_ttoi(tcpheaderlen) * 4).c_str()) + " bytes ("
			+ tcpheaderlen + ")";

		// Reserver+Flag;
		// 6bits -> Reserved
		uint8_t reservedValue = tcpLayer->getTcpHeader()->reserved;
		CString Reserved;
		Reserved.Format(_T("%03d"), reservedValue & 0x0F);
		CString Accurate_ECN = (tcpLayer->getTcpHeader()->cwrFlag) || (tcpLayer->getTcpHeader()->eceFlag) ? L"1" : L"0";
		CString CongestionWindowReduced = tcpLayer->getTcpHeader()->cwrFlag ? L"1" : L"0";
		CString ECN_Echo = tcpLayer->getTcpHeader()->eceFlag ? L"1" : L"0";

		// Flag
		// 6bits -> Flags
		CString Urgent = tcpLayer->getTcpHeader()->urgFlag ? L"1" : L"0";
		CString Acknowledgment = tcpLayer->getTcpHeader()->ackFlag ? L"1" : L"0";
		CString Push = tcpLayer->getTcpHeader()->pshFlag ? L"1" : L"0";
		CString Reset = tcpLayer->getTcpHeader()->rstFlag ? L"1" : L"0";
		CString Syn = tcpLayer->getTcpHeader()->synFlag ? L"1" : L"0";
		CString Fin = tcpLayer->getTcpHeader()->finFlag ? L"1" : L"0";
		CString TCPFlagBinaryOnly = Urgent + Acknowledgment + Push + Reset + Syn + Fin;

		uint16_t flags16Bit =
			(tcpLayer->getTcpHeader()->reserved << 8) |
			(tcpLayer->getTcpHeader()->cwrFlag << 7) |
			(tcpLayer->getTcpHeader()->eceFlag << 6) |
			(tcpLayer->getTcpHeader()->urgFlag << 5) |
			(tcpLayer->getTcpHeader()->ackFlag << 4) |
			(tcpLayer->getTcpHeader()->pshFlag << 3) |
			(tcpLayer->getTcpHeader()->rstFlag << 2) |
			(tcpLayer->getTcpHeader()->synFlag << 1) |
			tcpLayer->getTcpHeader()->finFlag;

		// 16진수 문자열로 변환
		CString flagsHexStr;
		flagsHexStr.Format(_T("%02X"), flags16Bit);

		// TCP Flags:  . . . . . . .A . . .F 의 형식
		CString TCPFlagLongStr = L". . . . . . ";
		TCPFlagLongStr += tcpLayer->getTcpHeader()->urgFlag ? L"U" : L".";
		TCPFlagLongStr += tcpLayer->getTcpHeader()->ackFlag ? L"A" : L".";
		TCPFlagLongStr += tcpLayer->getTcpHeader()->pshFlag ? L"P" : L".";
		TCPFlagLongStr += tcpLayer->getTcpHeader()->rstFlag ? L"R" : L".";
		TCPFlagLongStr += tcpLayer->getTcpHeader()->synFlag ? L"S" : L".";
		TCPFlagLongStr += tcpLayer->getTcpHeader()->finFlag ? L"F" : L".";


		CString PacketDataLine4by6 = L"Flags: 0x" + flagsHexStr + L"(" + Data::GetTCPFlagToStr(TCPFlagBinaryOnly) + L")";

		CString PacketDataLine4by6by1 = Reserved;
		CString PacketDataLine4by6by2 = Accurate_ECN;
		CString PacketDataLine4by6by3 = CongestionWindowReduced;
		CString PacketDataLine4by6by4 = ECN_Echo;
		CString PacketDataLine4by6by5 = Urgent;
		CString PacketDataLine4by6by6 = Acknowledgment;
		CString PacketDataLine4by6by7 = Push;
		CString PacketDataLine4by6by8 = Reset;
		CString PacketDataLine4by6by9 = Syn;
		CString PacketDataLine4by6by10 = Fin;
		CString PacketDataLine4by6by11 = L"[TCP Flags: " + TCPFlagLongStr + "]";

		PacketDataLine4by6by1 = Reserved + L".  . . . .  . . . . = Reserved: " + Data::GetFlagSetNotSet(Reserved);		// Reserved
		PacketDataLine4by6by2 = L". . . " + Accurate_ECN + L"  . . . .  . . . . = Accurate ECN: " + Data::GetFlagSetNotSet(Accurate_ECN);		// Nonce
		PacketDataLine4by6by3 = L". . . .  " + CongestionWindowReduced + L". . .  . . . . = Congestion Window Reduced (CWR) : " + Data::GetFlagSetNotSet(CongestionWindowReduced);		// CongestionWindowReduced
		PacketDataLine4by6by4 = L". . . .  . " + ECN_Echo + L". .  . . . . = ECN-Echo : " + Data::GetFlagSetNotSet(ECN_Echo);		// ECN_Echo
		PacketDataLine4by6by5 = L". . . .  . . " + Urgent + L".  . . . . = Urgent : " + Data::GetFlagSetNotSet(Urgent);		// Urgent
		PacketDataLine4by6by6 = L". . . .  . . ." + Acknowledgment + L"  . . . . = Acknowledgment : " + Data::GetFlagSetNotSet(Acknowledgment);		// Acknowledgment
		PacketDataLine4by6by7 = L". . . .  . . . .  " + Push + L". . . = Push : " + Data::GetFlagSetNotSet(Push);		// Push
		PacketDataLine4by6by8 = L". . . .  . . . .  . " + Reset + L". . = Reset : " + Data::GetFlagSetNotSet(Reset);		// Reset
		PacketDataLine4by6by9 = L". . . .  . . . .  . . " + Syn + L". = Syn : " + Data::GetFlagSetNotSet(Syn);		// Syn
		PacketDataLine4by6by10 = L". . . .  . . . .  . . ." + Fin + L" = Fin : " + Data::GetFlagSetNotSet(Fin);		// Fin


		CString winsize;
		winsize.Format(_T("%u"), ntohs(tcpLayer->getTcpHeader()->windowSize));

		CString urgepoint;
		urgepoint.Format(_T("%u"), tcpLayer->getTcpHeader()->urgentPointer);

		CString headerchecksum;
		headerchecksum.Format(_T("%04X"), pcpp::netToHost16(tcpLayer->getTcpHeader()->headerChecksum));

		CString PacketDataLine4by7 = L"Window size value: " + winsize;
		CString PacketDataLine4by8 = L"[Calculated window size: " + winsize + L"]";
		CString PacketDataLine4by9 = L"Checksum: 0x" + headerchecksum;
		CString PacketDataLine4by10 = L"Urgent pointer: " + urgepoint;

		// Line 4
		PacketDataRoot4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4);
		HTREEITEM PacketDataRoot4Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by1, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by2, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by3, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by4, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by5, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child6 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child6Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by1, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by2, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by3, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by4, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by5, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child6 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by6, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child7 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by7, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child8 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by8, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child9 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by9, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child10 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by10, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child11 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by11, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child7 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by7, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child8 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by8, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child9 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by9, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child10 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by10, PacketDataRoot4);

		goto UpdatePacketInfo;
	}

	//Line4 입력 UDP
	else if (Protocol == _T("UDP") || (Protocol == _T("DHCP")) || (Protocol == _T("DNS"))) {
		pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();

		CString UdpSrcPort;
		UdpSrcPort.Format(_T("%u"), udpLayer->getSrcPort());

		CString UdpDstPort;
		UdpDstPort.Format(_T("%u"), udpLayer->getDstPort());

		PacketDataLine4 = L"User Datagram protocol, Src Port: " + UdpSrcPort + L", Dst Port: " + UdpDstPort;

		CString Length;
		Length.Format(_T("%u"), pcpp::netToHost16(udpLayer->getUdpHeader()->length));

		CString checksum;
		checksum.Format(_T("%04X"), pcpp::netToHost16(udpLayer->getUdpHeader()->headerChecksum));

		CString PacketDataLine4by1 = L"Source Port: " + UdpSrcPort;
		CString PacketDataLine4by2 = L"Destination Port: " + UdpDstPort;
		CString PacketDataLine4by3 = L"Length: " + Length;
		CString PacketDataLine4by4 = L"Checksum: 0x" + checksum;

		PacketDataRoot4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4);
		HTREEITEM  PacketDataRoot4Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by1, PacketDataRoot4);
		HTREEITEM  PacketDataRoot4Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by2, PacketDataRoot4);
		HTREEITEM  PacketDataRoot4Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by3, PacketDataRoot4);
		HTREEITEM  PacketDataRoot4Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by4, PacketDataRoot4);

		if (parsedPacket.getLastLayer() == parsedPacket.getLayerOfType<pcpp::PayloadLayer>())
		{
			CString UDPDataLength;
			UDPDataLength.Format(_T("%u"), static_cast<unsigned int>(parsedPacket.getLayerOfType<pcpp::PayloadLayer>()->getPayloadLen()));
			CString PacketDataLine5 = L"UDP payload (" + UDPDataLength + " bytes)";
			PacketDataRoot5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine5);
		}
	}

	UpdatePacketInfo:
		m_PacketDataTreeCtrl.Expand(PacketDataRoot1, TVE_EXPAND);
		m_PacketDataTreeCtrl.Expand(PacketDataRoot2, TVE_EXPAND);
		m_PacketDataTreeCtrl.Expand(PacketDataRoot3, TVE_EXPAND);
		m_PacketDataTreeCtrl.Expand(PacketDataRoot4, TVE_EXPAND);
		m_PacketDataTreeCtrl.Expand(PacketDataRoot5, TVE_EXPAND);

		m_PacketDataTreeCtrl.Invalidate();
		m_PacketDataTreeCtrl.UpdateWindow();
}

void CPacketCaptureDlg::ChangePktCountText() {
	CString strText;
	strText.Format(L"All: %d TCP: %d UDP: %d ARP %d ICMP %d",
		stats.ethPacketCount, stats.tcpPacketCount, stats.udpPacketCount, stats.arpPacketCount, stats.icmpPacketCount);
	SetDlgItemText(IDC_STATIC_PACKETCNT, strText);
}


void CPacketCaptureDlg::OnBnClickedStartButton()
{
	// 네트워크 디바이스 목록에서 선택된 장치 찾기
	pcpp::PcapLiveDevice* dev = nullptr;
	for (const auto& device : m_DeviceList) {
		CString deviceName(device->getName().c_str());
		if (deviceName.Compare(m_SelectedDeviceName) == 0) {
			dev = device;
			break;
		}
	}

	//장치 오류에 따른 경고 알림창
	if (!dev) {
		MessageBox(_T("Selected interface not found."), _T("Error"), MB_OK | MB_ICONWARNING);
		return;
	}

	if (!dev->open()) {
		MessageBox(_T("Cannot open device."), _T("Error"), MB_OK | MB_ICONWARNING);
		return;
	}

	if (m_PacketCaptureThreadWorkType == RUNNING) {
		MessageBox(_T("Already Start Capture"), _T("Error"), MB_OK | MB_ICONWARNING);
		return;
	}

	// 캡처된 패킷 정보가 저장된 파일이 있을 경우 삭제
	std::string fileName = "captured_packets.dat";							
	if (remove(fileName.c_str()) == 0) {
		GetDlgItem(IDC_FILTER_BUTTON)->EnableWindow(TRUE);
		GetDlgItem(IDC_NET_SELECT)->EnableWindow(FALSE);
	}
	// ENOENT는 파일이 존재하지 않는 경우의 에러 코드
	else if (errno != ENOENT) {												
		MessageBox(_T("Failed to delete previous capture file."), _T("Error"), MB_OK | MB_ICONWARNING);
		return;
	}

	// 기존 화면의 패킷 정보 삭제
	stats.clear();
	m_PacketCaptureListCtrl.DeleteAllItems();
	m_PacketDumpListCtrl.DeleteAllItems();
	m_PacketDataTreeCtrl.DeleteAllItems();


	//캡처가 시작되면 문구를 띄우고 시작 플래그 설정. Stop 버튼 비활성화'this'는 현재 CPacketCaptureDlg 객체의 포인터
	if (dev->startCapture(CPacketCaptureDlg::onPacketArrives, this))
	{
		SetDlgItemText(IDC_STATIC_STATE, _T("Start Packet Capture"));
		m_PacketCaptureThreadWorkType = RUNNING;
		GetDlgItem(IDC_STOP_BUTTON)->EnableWindow(true);
		
	}
	else {
		MessageBox(_T("Cannot Start Capture"), _T("Error"), MB_OK | MB_ICONWARNING);
	}
}


void CPacketCaptureDlg::OnBnClickedStopButton()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	if (m_PacketCaptureThreadWorkType == RUNNING) {
		pcpp::PcapLiveDevice* dev = nullptr;
		for (const auto& device : m_DeviceList) {
			CString deviceName(device->getName().c_str());
			if (deviceName.Compare(m_SelectedDeviceName) == 0) {
				dev = device;
				break;
			}
		}
		if (dev) {
			dev->stopCapture();
			dev->close();
			m_PacketCaptureThreadWorkType = STOP;
			GetDlgItem(IDC_STOP_BUTTON)->EnableWindow(FALSE);
			GetDlgItem(IDC_NET_SELECT)->EnableWindow(TRUE);
			SetDlgItemText(IDC_STATIC_STATE, _T("Stop Packet Capture"));
		}
		else {
			MessageBox(_T("Cannot found selected device."), _T("Error"), MB_OK | MB_ICONERROR);
		}
	}
}


void CPacketCaptureDlg::OnBnClickedFilterButton()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	CString InputText;
	m_edit1.GetWindowTextW(InputText);

	// 유니코드 CString을 ASCII std::string으로 변환
	CT2CA pszConvertedAnsiString(InputText);
	std::string InputText_Filter(pszConvertedAnsiString);

	// 기존 필터 삭제 : 이전 필터 객체가 메모리에 남아있지 않도록
	if (m_pFilter)
	{
		delete m_pFilter;
		m_pFilter = nullptr;
	}

	// 새로운 필터 객체 생성 
	m_pFilter = new pcpp::BPFStringFilter(InputText_Filter);
	if (!m_pFilter->verifyFilter())
	{
		MessageBox(_T("Unsupported Filtering Format"), _T("Error"), MB_OK | MB_ICONWARNING);
		delete m_pFilter;
		m_pFilter = nullptr;
		return;
	}

	// 리스트 컨트롤 초기화
	m_PacketCaptureListCtrl.DeleteAllItems();
	
	std::ifstream inFile("captured_packets.dat", std::ios::binary);
	if (!inFile.is_open())
	{
		MessageBox(_T("Cannot Open Packet File"), _T("Error"), MB_OK | MB_ICONWARNING);
		return;
	}

	while (true)
	{
		uint32_t dataLen = 0;
		inFile.read(reinterpret_cast<char*>(&dataLen), sizeof(dataLen));

		if (inFile.eof() || dataLen == 0)
			break;

		std::vector<uint8_t> buffer(dataLen);
		inFile.read(reinterpret_cast<char*>(buffer.data()), dataLen);

		// 타임스탬프 읽기
		time_t sec;
		long nsec;
		inFile.read(reinterpret_cast<char*>(&sec), sizeof(sec));
		inFile.read(reinterpret_cast<char*>(&nsec), sizeof(nsec));

		timespec timestamp;
		timestamp.tv_sec = sec;
		timestamp.tv_nsec = nsec;

		
		pcpp::RawPacket rawPacket(buffer.data(), dataLen, timestamp, false);

		if (m_pFilter && !m_pFilter->matchPacketWithFilter(&rawPacket))
		{
			continue;
		}

		Filter::PacketInfo packetInfo = Filter::FilterFunction::FilterdPacketInfo(&rawPacket);

		int column_count = m_PacketCaptureListCtrl.GetItemCount();
		CString column_count_str;
		column_count_str.Format(_T("%d"), column_count + 1);

		m_PacketCaptureListCtrl.InsertItem(column_count, column_count_str);
		m_PacketCaptureListCtrl.SetItemText(column_count, 1, packetInfo.PacketTimeStr);
		m_PacketCaptureListCtrl.SetItemText(column_count, 2, packetInfo.SrcIP);
		m_PacketCaptureListCtrl.SetItemText(column_count, 3, packetInfo.DstIP);
		m_PacketCaptureListCtrl.SetItemText(column_count, 4, packetInfo.Protocol);
		m_PacketCaptureListCtrl.SetItemText(column_count, 5, packetInfo.Length);
		m_PacketCaptureListCtrl.SetItemText(column_count, 6, packetInfo.Info);
	}

	inFile.close();
}


void CPacketCaptureDlg::SetDataToHDXEditor(CString Packet_dump_data) {
	if (Packet_dump_data != L"") {
		for (int i = 0; i < Packet_dump_data.GetLength() + 1; i += 32) {
			int column_count = m_PacketDumpListCtrl.GetItemCount();
			CString column_count_str;
			column_count_str.Format(_T("%d"), column_count + 1);

			std::stringstream stream;
			stream << std::setw(6) << std::setfill('0') << std::hex << (i / 2);

			std::string seq_number_str = stream.str();
			LPCSTR lpcstrSeqNum = (LPCSTR)seq_number_str.c_str();
			USES_CONVERSION;
			CString CstrSeqNum = A2CT(lpcstrSeqNum);
			CstrSeqNum.MakeUpper();
			m_PacketDumpListCtrl.InsertItem(column_count, CstrSeqNum);

			CString allHex = Packet_dump_data.Mid(i, 32);
			CString AsciiAllHex = allHex;
			allHex = allHex.MakeUpper();

			CString hex1, hex2;

			for (int i = 0; i < 16; i += 2) {
				hex1 += allHex.Mid(i, 2) + L"  ";
			}

			for (int i = 16; i < 32; i += 2) {
				hex2 += allHex.Mid(i, 2) + L"  ";
			}

			m_PacketDumpListCtrl.SetItem(column_count, 1, LVIF_TEXT, hex1, NULL, NULL, NULL, NULL);
			m_PacketDumpListCtrl.SetItem(column_count, 2, LVIF_TEXT, hex2, NULL, NULL, NULL, NULL);

			CString convAscii;
			CString PacketAscii1;
			CString PacketAscii2;

			for (int i = 0; i < AsciiAllHex.GetLength(); i += 2) {
				PacketAscii1 = Data::HexToDec(AsciiAllHex.Mid(i, 1));
				PacketAscii2 = Data::HexToDec(AsciiAllHex.Mid(i + 1, 1));

				int ten = _ttoi(PacketAscii1) * 16;
				int one = _ttoi(PacketAscii2);

				int sum = ten + one;
				ten = 0;
				one = 0;

				if (sum < 32 || sum>128) {
					sum = 46;
				}

				char ascii[4];
				ascii[0] = (char)sum;
				if (sum == 46) {
					sprintf(ascii, "%2c", ascii[0]);
				}
				else {
					sprintf(ascii, "%c", ascii[0]);
				}
				convAscii += ascii;
			}
			m_PacketDumpListCtrl.SetItem(column_count, 3, LVIF_TEXT, convAscii, NULL, NULL, NULL, NULL);
		}
	}
}


void CPacketCaptureDlg::OnFileSave()
{
	// TODO: 여기에 명령 처리기 코드를 추가합니다.
	bool SaveSuccess = false;

	CFileDialog f_dlg(FALSE, _T("pcap"), _T(" * .pcap; *.pcapng"),
		OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY,
		_T("PCAP Files (*.pcap, *.pcapng)|*.pcap; *.pcapng||", this));

	if (f_dlg.DoModal() != IDOK)
	{
		return; // 사용자가 취소를 눌렀을 경우
	}

	CString strFilePath = f_dlg.GetPathName();

	// CString을 std::string으로 변환
	CT2CA pszConvertedAnsiString(strFilePath);
	std::string stdStrFilePath(pszConvertedAnsiString);

	//파일 저장명 확장자 추출
	CString StrFileExt = f_dlg.GetFileExt();

	//pcap파일로 저장한 경우
	if (StrFileExt == "pcap") {
		pcpp::PcapFileWriterDevice pcapWriter(stdStrFilePath, pcpp::LINKTYPE_ETHERNET);

		if (!pcapWriter.open())
		{
			AfxMessageBox(_T("Error opening file for writing."));
			return;
		}

		std::ifstream inFile("captured_packets.dat", std::ios::binary);
		if (!inFile.is_open())
		{
			AfxMessageBox(_T("Error opening captured_packets.dat for reading."));
			return;
		}

		while (true)
		{
			uint32_t dataLen = 0;
			inFile.read(reinterpret_cast<char*>(&dataLen), sizeof(dataLen));

			if (inFile.eof() || dataLen == 0)
				break;

			std::vector<uint8_t> buffer(dataLen);
			inFile.read(reinterpret_cast<char*>(buffer.data()), dataLen);

			// 타임스탬프 읽기
			time_t sec;
			long nsec;
			inFile.read(reinterpret_cast<char*>(&sec), sizeof(sec));
			inFile.read(reinterpret_cast<char*>(&nsec), sizeof(nsec));

			timespec timestamp;
			timestamp.tv_sec = sec;
			timestamp.tv_nsec = nsec;

			pcpp::RawPacket rawPacket(buffer.data(), dataLen, timestamp, false);

			if (!pcapWriter.writePacket(rawPacket))
			{
				AfxMessageBox(_T("Error writing packet to pcap file."));
				break;
			}
		}
		pcapWriter.close();
		SaveSuccess = true;
		inFile.close();
	}

	//pcapng파일로 저장한 경우
	else if (StrFileExt == "pcapng") {
		pcpp::PcapNgFileWriterDevice pcapNgWriter(stdStrFilePath, pcpp::LINKTYPE_ETHERNET);

		if (!pcapNgWriter.open())
		{
			AfxMessageBox(_T("Error opening file for writing."));
			return;
		}
		
		std::ifstream inFile("captured_packets.dat", std::ios::binary);
		if (!inFile.is_open())
		{
			AfxMessageBox(_T("Error opening captured_packets.dat for reading."));
			return;
		}
		
		while (true)
		{
			uint32_t dataLen = 0;
			inFile.read(reinterpret_cast<char*>(&dataLen), sizeof(dataLen));

			if (inFile.eof() || dataLen == 0)
				break;

			std::vector<uint8_t> buffer(dataLen);
			inFile.read(reinterpret_cast<char*>(buffer.data()), dataLen);

			// 타임스탬프 읽기
			time_t sec;
			long nsec;
			inFile.read(reinterpret_cast<char*>(&sec), sizeof(sec));
			inFile.read(reinterpret_cast<char*>(&nsec), sizeof(nsec));

			timespec timestamp;
			timestamp.tv_sec = sec;
			timestamp.tv_nsec = nsec;

			pcpp::RawPacket rawPacket(buffer.data(), dataLen, timestamp, false);

			if (!pcapNgWriter.writePacket(rawPacket))
			{
				AfxMessageBox(_T("Error writing packet to pcap file."));
				break;
			}
		}
		pcapNgWriter.close();
		SaveSuccess = true;
		inFile.close();
	}
	if (SaveSuccess)
	{
		MessageBox(L"File saved successfully.", L"Success");
	}
}


void CPacketCaptureDlg::OnFileOpen()
{
	// TODO: 여기에 명령 처리기 코드를 추가합니다.
	// 파일 선택 다이얼로그 열기
	CFileDialog dlg(TRUE, _T("pcap"), _T("*.pcap;*.pcapng"), OFN_FILEMUSTEXIST | OFN_HIDEREADONLY, _T("PCAP Files (*.pcap, *.pcapng)|*.pcap; *.pcapng||"));
	
	if (dlg.DoModal() != IDOK)
	{
		return;  // 사용자가 취소를 눌렀을 경우
	}

	stats.clear();

	CString cstrFilePath = dlg.GetPathName();

	// CString을 std::string으로 변환
	CT2CA pszConvertedAnsiString(cstrFilePath);
	std::string strFilePath(pszConvertedAnsiString); //CString을 std::string으로 변환

	// PCAP 파일 리더 객체 생성
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(strFilePath);

	if (reader == nullptr)
	{

		MessageBox(_T("Error opening the file"), _T("Error"), MB_OK | MB_ICONWARNING);
		return;
	}

	// 파일 열기
	if (!reader->open())
	{
		MessageBox(_T("Error opening the file"), _T("Error"), MB_OK | MB_ICONWARNING);

		delete reader;
		return;
	}

	m_PacketDataTreeCtrl.DeleteAllItems();
	m_PacketDumpListCtrl.DeleteAllItems();
	m_PacketCaptureListCtrl.DeleteAllItems();

	// 패킷 읽기 및 처리
	pcpp::RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket))
	{
		onPacketArrives(&rawPacket, nullptr, this);
		OnUpdateUI(0, 0);
	}
	// 파일 닫기
	reader->close();

	// 리더 객체 삭제
	delete reader;
	MessageBox(L"File open successfully.", L"Success");
}


void CPacketCaptureDlg::OnBnClickedNetSelect()
{
// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	int nCurSel = m_NetworkComboBox.GetCurSel();
	if (nCurSel == CB_ERR) {
		MessageBox(_T("Please Select NetworkInterface"), _T("Error"), MB_OK | MB_ICONWARNING);
		return;
	}

	// 선택된 인덱스를 통해 디바이스 정보 가져오기
	auto selectedDevice = m_DeviceList[nCurSel];

	// 디바이스 정보를 변수에 저장
	CString selectedDeviceName(selectedDevice->getName().c_str());
	CString selectedDeviceDesc(selectedDevice->getDesc().c_str());

	// 필요에 따라 저장할 변수
	m_SelectedDeviceName = selectedDeviceName;
	m_SelectedDeviceDesc = selectedDeviceDesc;

	SelectedNetworkInterfaceInfo();

}



void CPacketCaptureDlg::OnUpdateFileSave(CCmdUI* pCmdUI)
{
	// TODO: 여기에 명령 업데이트 UI 처리기 코드를 추가합니다.
	if(m_PacketCaptureThreadWorkType == RUNNING)
		pCmdUI->Enable(false);
	 else
		pCmdUI->Enable(true);
}


void CPacketCaptureDlg::OnUpdateFileOpen(CCmdUI* pCmdUI)
{
	// TODO: 여기에 명령 업데이트 UI 처리기 코드를 추가합니다.
	if (m_PacketCaptureThreadWorkType == RUNNING)

		pCmdUI->Enable(false);
	else
		pCmdUI->Enable(true);
}
