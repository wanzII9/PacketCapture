
// PacketCaptureDlg.h: 헤더 파일
//
#include <WinPcapLiveDevice.h>
#include <queue>
#include <mutex>

#pragma once
#define WM_UPDATE_STATS (WM_USER + 1)	//사용자 지정 메시지를 정의


// CPacketCaptureDlg 대화 상자
class CPacketCaptureDlg : public CDialogEx
{
// 생성입니다.
public:
	CPacketCaptureDlg(CWnd* pParent = nullptr);	// 표준 생성자입니다.

	static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);
	void CPacketCaptureDlg::ChangePktCountText();

	struct PacketStats
	{
		int ethPacketCount;
		int tcpPacketCount;
		int udpPacketCount;
		int arpPacketCount;
		int icmpPacketCount;


		void clear() {
			ethPacketCount = 0; tcpPacketCount = 0;
			udpPacketCount = 0; arpPacketCount = 0; icmpPacketCount = 0;
		}

		void consumePacket(pcpp::Packet& packet)
		{
			if (packet.isPacketOfType(pcpp::Ethernet))
				ethPacketCount++;
			if (packet.isPacketOfType(pcpp::TCP))
				tcpPacketCount++;
			if (packet.isPacketOfType(pcpp::UDP))
				udpPacketCount++;
			if (packet.isPacketOfType(pcpp::ARP))
				arpPacketCount++;
			if (packet.isPacketOfType(pcpp::ICMP))
				icmpPacketCount++;
		}
	};

	PacketStats stats;

	struct PacketInfo
	{
		CString PacketTimeStr;
		CString SrcIP;
		CString DstIP;
		CString Protocol;
		CString Length;
		CString Info;
	};

	std::queue<PacketInfo> packetQueue;
	std::mutex queueMutex;

	std::vector<pcpp::RawPacket> capturedPackets;
	std::mutex packetsMutex;

	pcpp::BPFStringFilter* m_pFilter = nullptr;

	BOOL CursorPositionLast = TRUE;

	int PrevClickColumnNumber = -1;


// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PACKETCAPTURE_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 지원입니다.



// 구현입니다.
protected:
	HICON m_hIcon;

	// 생성된 메시지 맵 함수
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg LRESULT OnUpdateUI(WPARAM wParam, LPARAM lParam);	//메시지 처리기 추가
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedStartButton();
	afx_msg void OnBnClickedStopButton();
	afx_msg void OnBnClickedFilterButton();
	afx_msg void OnFileSave();
	afx_msg void OnFileOpen();
	afx_msg void CPacketCaptureDlg::OnNMDblclkList(NMHDR* pNMHDR, LRESULT* pResult);

	CListCtrl m_PacketCaptureListCtrl;
	void OnCustomdrawList(NMHDR* pNMHDR, LRESULT* pResult);


	enum ThreadWorking {
		STOP = 0,
		RUNNING = 1
	};

	ThreadWorking m_PacketCaptureThreadWorkType = STOP;

	void PacketDetail(pcpp::RawPacket* packet, CString FrameNumber, CString Time, CString Source,
		CString Destination, CString Protocol, CString Length);

	void CPacketCaptureDlg::SetDataToHDXEditor(CString Packet_dump_data);
	void CPacketCaptureDlg::SelectedNetworkInterfaceInfo();

	CTreeCtrl m_PacketDataTreeCtrl;
	
	CEdit m_edit1;
	CListCtrl m_PacketDumpListCtrl;
	CStatic m_static1;
	CComboBox m_NetworkComboBox;
	afx_msg void OnBnClickedNetSelect();
	std::vector<pcpp::PcapLiveDevice*> m_DeviceList;
	CString m_SelectedDeviceName;
	CString m_SelectedDeviceDesc;
	CStatic m_static2;
	CStatic m_static3;
	afx_msg void OnUpdateFileSave(CCmdUI* pCmdUI);
	afx_msg void OnUpdateFileOpen(CCmdUI* pCmdUI);
};
