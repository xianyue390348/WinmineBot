
// WinmineDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Winmine.h"
#include "WinmineDlg.h"
#include "afxdialogex.h"
#include "TlHelp32.h"



#ifdef _DEBUG
#define new DEBUG_NEW
#endif

DWORD pid = 0;
HANDLE hProc = 0;
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框
void Click(int x, int y);
class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CWinmineDlg 对话框



CWinmineDlg::CWinmineDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_WINMINE_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CWinmineDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CWinmineDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CWinmineDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CWinmineDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CWinmineDlg::OnBnClickedButton3)
END_MESSAGE_MAP()


// CWinmineDlg 消息处理程序

BOOL CWinmineDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	HANDLE hProcessShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessShot == INVALID_HANDLE_VALUE)
		AfxMessageBox(L"枚举进程失败！");
	PROCESSENTRY32 procinfo;
	procinfo.dwSize = sizeof(PROCESSENTRY32);
	DWORD pid = 0;
	if (Process32First(hProcessShot, &procinfo)) {
		do {
			CString name(procinfo.szExeFile);
			if (name == L"winmine.exe") {
				//是该进程
				pid = procinfo.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcessShot, &procinfo));
	}
	if (pid == 0) {
		AfxMessageBox(L"请先启动扫雷进程！winmine.exe");
		exit(0);
	}
	hProc = OpenProcess(0x0000043A, false, pid);
	if (hProc == NULL) {
		AfxMessageBox(L"打开扫雷进程失败！请尝试使用管理员权限！");
	}

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CWinmineDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CWinmineDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CWinmineDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CWinmineDlg::OnBnClickedButton1()
{
	CHAR shellcode[] = { 0x6A,0x01,0xE8,0x00,0x00,0x00,0x00,0x33,0xC0,0xC2,0x04,0x00};
	auto address = VirtualAllocEx(hProc, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	*(DWORD*)&shellcode[3] = Calc_Call((DWORD)address+2, 0x0100347c);
	if (address == NULL) {
		AfxMessageBox(L"申请远程内存出错！");
	}
	if (!WriteProcessMemory(hProc, address, (LPCVOID)&shellcode, sizeof(shellcode), NULL)) {
		AfxMessageBox(L"写远程地址内存出错！");
	}
	auto ht = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)address, NULL, 0, NULL);
	WaitForSingleObject(ht, INFINITE);
	VirtualFreeEx(hProc, address, sizeof(shellcode), MEM_DECOMMIT);
}


void CWinmineDlg::OnBnClickedButton2()
{
	DWORD x_size = 0,y_size = 0;
	ReadProcessMemory(hProc, (LPVOID)0x010056AC, &x_size, sizeof(DWORD), NULL);
	ReadProcessMemory(hProc, (LPVOID)0x010056A8, &y_size, sizeof(DWORD), NULL);
	/*CString str;
	str.Format(L"x=%d,y=%d", x_size, y_size);
	MessageBox(str);*/
	CHAR *blk = new CHAR[(y_size+2) *32];
	ReadProcessMemory(hProc, (LPVOID)0x01005340, blk, (y_size+2) * 32, NULL);
	CString temp = L"";
	CString char_str;
	//CHAR A = blk[4 * 32 + 7];
	//CHAR B = blk[4 * 32 + 8];
	//CHAR C = blk[4 * 32 + 9];
	CString all;
	for (int y = 1; y <= y_size; y++) {
		for (int x = 1; x <= x_size; x++) {
			CHAR a = blk[y * 32 + x];
			temp.Format(L"%2x", a);
			all += temp +L" ";
			if (a != '\xf') {
				Mark(y,x);
			}
			else {
				Click(y,x);
			}
			Sleep(50);
		}all += "\r\n";
	}
	MessageBox(all);
}

struct m_point
{
	int x;
	int y;
};
void CWinmineDlg::Click(int x, int y)
{
	char s_x, s_y;
	s_x = x;
	s_y = y;
	CHAR shellcode[] = { 0x6A,0x01,0x6A,0x01,0xE8,0x00,0x00,0x00,0x00,0x33,0xC0,0xC2,0x04,0x00 };
	shellcode[1] = s_x;
	shellcode[3] = s_y;
	auto address = VirtualAllocEx(hProc, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	*(DWORD*)&shellcode[5] = Calc_Call((DWORD)address + 4, 0x01003084);
	if (address == NULL) {
		AfxMessageBox(L"申请远程内存出错！");
	}
	if (!WriteProcessMemory(hProc, address, (LPCVOID)&shellcode, sizeof(shellcode), NULL)) {
		AfxMessageBox(L"写远程地址内存出错！");
	}
	auto ht = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)address, NULL, 0, NULL);
	WaitForSingleObject(ht, INFINITE);
	VirtualFreeEx(hProc, address, sizeof(shellcode), MEM_DECOMMIT);
}

void CWinmineDlg::OnBnClickedButton3()
{
	//Click(1, 1);
	Mark(2, 2);
}


DWORD CWinmineDlg::Calc_Call(DWORD now, DWORD target)
{
	return target - now - 5;
}

void CWinmineDlg::Mark(int x, int y)
{
	char s_x, s_y;
	s_x = x;
	s_y = y;
	CHAR shellcode[] = { 0x6A,0x01,0x6A,0x01,0xE8,0x00,0x00,0x00,0x00,0x33,0xC0,0xC2,0x04,0x00 };
	shellcode[1] = s_x;
	shellcode[3] = s_y;
	auto address = VirtualAllocEx(hProc, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	*(DWORD*)&shellcode[5] = Calc_Call((DWORD)address + 4, 0x0100374F);
	if (address == NULL) {
		AfxMessageBox(L"申请远程内存出错！");
	}
	if (!WriteProcessMemory(hProc, address, (LPCVOID)&shellcode, sizeof(shellcode), NULL)) {
		AfxMessageBox(L"写远程地址内存出错！");
	}
	auto ht = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)address, NULL, 0, NULL);
	WaitForSingleObject(ht, INFINITE);
	VirtualFreeEx(hProc, address, sizeof(shellcode), MEM_DECOMMIT);
}