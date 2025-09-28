#define WIN32_LEAN_AND_MEAN // �ų��޹ص� Windows ͷ�ļ�
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <Windows.h>

#include <objidl.h> // �������gdiplus.h֮ǰ

#include <Lmcons.h>
#include <UserEnv.h>
#include <WtsApi32.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <codecvt>
#include <condition_variable>
#include <ctime>
#include <fstream>
#include <functional>
#include <future>
#include <gdiplus.h>
#include <iomanip>
#include <iostream>
#include <iphlpapi.h>
#include <locale>
#include <map>
#include <mutex>
#include <queue>
#include <sddl.h>
#include <sstream>
#include <stdio.h>
#include <string>
#include <strsafe.h>
#include <tchar.h>
#include <thread>
#include <tlhelp32.h>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>


#pragma comment(lib, "ws2_32.lib")   // Winsock�����⣨�����һ����
#pragma comment(lib, "iphlpapi.lib") // ����Winsock����
#pragma comment(lib, "Wtsapi32.lib") // Զ���������
#pragma comment(lib, "Userenv.lib")  // �û���������
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "ole32.lib")

using namespace Gdiplus;
using namespace std;

int httpServerPort = 22200;

std::wstring g_AppName = L"WinDesktop";
std::wstring g_regPath = L"SOFTWARE\\" + g_AppName;
std::string g_logPath = "C:\\screenshots\\a.log";

HDESK g_hOriginalDesktop = NULL;
HDESK g_hInputDesktop = NULL;
bool g_isLock = false;
std::thread g_listenerThread;

int streamPort = 23200;
const int FPS = 30;
const auto FRAME_INTERVAL = chrono::milliseconds(1000 / FPS);
atomic<bool> g_streamRunning(true);

class AsyncLogger {
public:
    // ��ȡ����ʵ��
    static AsyncLogger& GetInstance() {
        static AsyncLogger instance(g_logPath);
        return instance;
    }

    // �ɱ����ģ��汾
    template <typename... Args> void log(Args &&...args) {
        std::string formatted_entry = formatEntry(std::forward<Args>(args)...);
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_queue.push(std::move(formatted_entry));
        }
        m_cond.notify_one();
    }

private:
    // ˽�й��죨����ģʽ��
    AsyncLogger(const std::string& file_path)
        : m_file_path(file_path), m_running(true),
        m_thread(std::bind(&AsyncLogger::processEntries, this)) {
    }

    ~AsyncLogger() {
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_running = false;
        }
        m_cond.notify_one();
        m_thread.join();
        flushRemaining();
    }

    // �ݹ���ֹ����
    void formatHelper(std::ostringstream& oss) {}

    // �ݹ�չ��������
    template <typename T, typename... Args>
    void formatHelper(std::ostringstream& oss, T&& first, Args &&...rest) {
        oss << std::forward<T>(first);
        if (sizeof...(rest) != 0) {
            oss << " "; // �������ÿո�ָ�
        }
        formatHelper(oss, std::forward<Args>(rest)...);
    }

    // ��ʽ������Ϊ�ַ���
    template <typename... Args> std::string formatEntry(Args &&...args) {
        std::ostringstream oss;
        oss << getCurrentTimestamp() << " ";
        formatHelper(oss, std::forward<Args>(args)...);
        return oss.str();
    }

    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) %
            1000;

        std::tm tm_buffer;
        localtime_s(&tm_buffer, &in_time_t); // ʹ�ð�ȫ��localtime_s���localtime

        std::stringstream ss;
        ss << std::put_time(&tm_buffer, "%Y-%m-%d %H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    void processEntries() {
        std::unique_lock<std::mutex> lock(m_mutex);

        while (m_running || !m_queue.empty()) {
            m_cond.wait(lock, [this]() { return !m_running || !m_queue.empty(); });

            decltype(m_queue) local_queue;
            local_queue.swap(m_queue);
            lock.unlock();

            writeToFile(local_queue);

            lock.lock();
        }
    }

    void writeToFile(std::queue<std::string>& entries) {
        std::ofstream file(m_file_path, std::ios::app);
        if (!file) {
            std::cerr << getCurrentTimestamp()
                << " [ERROR] Failed to open log file: " << m_file_path
                << std::endl;
            return;
        }

        while (!entries.empty()) {
            file << entries.front() << std::endl;
            entries.pop();
        }
    }

    void flushRemaining() {
        std::queue<std::string> remaining;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            remaining.swap(m_queue);
        }
        writeToFile(remaining);
    }

    AsyncLogger(const AsyncLogger&) = delete;
    AsyncLogger& operator=(const AsyncLogger&) = delete;

private:
    std::string m_file_path;
    std::queue<std::string> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cond;
    std::atomic<bool> m_running;
    std::thread m_thread;
};

// wchar_tתstd::string
std::string wchar_to_string(const wchar_t* wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

// std::wstringתstd::string
std::string wstring_to_string(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

// ����������UTF-8 string �� wstring
std::wstring UTF8ToWide(const std::string& str) {
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (size == 0)
        return L"";

    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
    return result;
}

void LogToFile(const std::string& message) {
    std::ofstream file("C:\\lock_screen_keys.log", std::ios::app);
    if (file) {
        file << message << std::endl;
    }
}

BOOL handleOpenInputDesktop() {
    g_hOriginalDesktop = GetThreadDesktop(GetCurrentThreadId());
    g_hInputDesktop = NULL;

    g_hInputDesktop = OpenInputDesktop(0, FALSE,
        DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW | DESKTOP_ENUMERATE |
        DESKTOP_HOOKCONTROL | DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS |
        DESKTOP_SWITCHDESKTOP | GENERIC_WRITE);

    if (!g_hInputDesktop) {
       /* AsyncLogger::GetInstance().log("OpenInputDesktop failed",
            std::to_string(GetLastError()));*/
        return FALSE;
    }

    if (!SetThreadDesktop(g_hInputDesktop)) {
        /*AsyncLogger::GetInstance().log("SetThreadDesktop failed",
            std::to_string(GetLastError()));*/

        SetThreadDesktop(g_hOriginalDesktop);

        if (g_hInputDesktop) {
            CloseDesktop(g_hInputDesktop);
        }
        return FALSE;  // ��ӷ���FALSE
    }
    //AsyncLogger::GetInstance().log("SetThreadDesktop OK");
    return TRUE;  // ��ӷ���TRUE
}


BOOL IsCurrentInputDesktop() {
    //AsyncLogger::GetInstance().log("IsCurrentInputDesktop ok");
    HDESK current = GetThreadDesktop(GetCurrentThreadId());
    HDESK input = OpenInputDesktop(
        0, FALSE,
        DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW | DESKTOP_ENUMERATE |
        DESKTOP_HOOKCONTROL | DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS |
        DESKTOP_SWITCHDESKTOP | GENERIC_WRITE);
    if (!input) {
        return FALSE;
    }

    DWORD size;
    char currentname[256];
    char inputname[256];

    if (!GetUserObjectInformation(current, UOI_NAME, currentname,
        sizeof(currentname), &size)) {
        CloseDesktop(input);
        return FALSE;
    }
    if (!GetUserObjectInformation(input, UOI_NAME, inputname, sizeof(inputname),
        &size)) {
        CloseDesktop(input);
        return FALSE;
    }
    CloseDesktop(input);
    // flog("%s %s\n", currentname, inputname);
    return strcmp(currentname, inputname) == 0 ? TRUE : FALSE;
}


struct GDIPlusInitializer {
    ULONG_PTR token;
    GdiplusStartupInput input;

    GDIPlusInitializer() {
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        GdiplusStartup(&token, &input, NULL);
    }
    ~GDIPlusInitializer() {
        GdiplusShutdown(token);
        CoUninitialize();
    }
};

void handleLoopGetCursorPos() {
    while (true) {

        if (IsCurrentInputDesktop()) {
            g_isLock = false;
            AsyncLogger::GetInstance().log("��ǰ���������");
        }
        else {
            g_isLock = true;
            AsyncLogger::GetInstance().log("��ǰ�����������");
        }

        // POINT pos;
        // if (GetCursorPos(&pos) != 0) {
        //   g_isLock = false;
        //   AsyncLogger::GetInstance().log("��ǰ��������");
        // } else {
        //   g_isLock = true;
        //   AsyncLogger::GetInstance().log("��ǰ������������",
        //                                  std::to_string(GetLastError()));
        // }

        Sleep(900);
    }
}

// д��ע���ֵ���ַ�����
bool WriteStringToRegistry(const std::string& valueNameUTF8,
    const std::string& strValueUTF8) {
    HKEY hKey;
    LONG result;

    // 1. ת�������ַ���ΪUTF-16
    std::wstring valueName = UTF8ToWide(valueNameUTF8);
    std::wstring strValue = UTF8ToWide(strValueUTF8);

    // 2. ��ע����
    result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, g_regPath.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey,
        nullptr);

    if (result != ERROR_SUCCESS) {
        return false;
    }

    // 3. д��ֵ��REG_SZ���ͣ�
    result = RegSetValueExW(hKey,
        valueName.c_str(), // ת����Ŀ��ַ�����
        0, REG_SZ,
        reinterpret_cast<const BYTE*>(strValue.c_str()),
        (strValue.size() + 1) * sizeof(wchar_t) // ������ֹ��
    );

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

// ��ȡע���ֵ���ַ�����
std::wstring ReadStringFromRegistry(const std::wstring& valueName) {
    HKEY hKey;
    LONG result;

    // 1. ��ע����
    result =
        RegOpenKeyEx(HKEY_LOCAL_MACHINE, g_regPath.c_str(), 0, KEY_READ, &hKey);

    if (result != ERROR_SUCCESS) {
        return L"";
    }

    // 2. ��ȡֵ���ͺʹ�С
    DWORD dataType = 0;
    DWORD dataSize = 0;
    result = RegQueryValueEx(hKey, valueName.c_str(), nullptr,
        &dataType, // ��������ȡ��������
        nullptr, &dataSize);

    if (result != ERROR_SUCCESS || dataSize == 0) {
        RegCloseKey(hKey);
        return L"";
    }

    // 3. ��ȡԭʼ����
    std::vector<BYTE> buffer(dataSize);
    result = RegQueryValueEx(hKey, valueName.c_str(), nullptr, &dataType,
        buffer.data(), &dataSize);

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        return L"";
    }

    // 4. �����������ʹ���
    if (dataType == REG_SZ || dataType == REG_EXPAND_SZ) {
        // �ַ������ͣ��Ƴ�ϵͳ�Զ���ӵ���ֹ������������ʵ��ֹ��ʱ��
        wchar_t* strData = reinterpret_cast<wchar_t*>(buffer.data());
        size_t len = dataSize / sizeof(wchar_t);
        if (len > 0 && strData[len - 1] == L'\0') {
            len--;
        }
        return std::wstring(strData, len);
    }
    else if (dataType == REG_MULTI_SZ) {
        // ���ַ������ͣ����\0��β���ַ�����
        // ʾ������ȡ��һ���ַ���
        wchar_t* strData = reinterpret_cast<wchar_t*>(buffer.data());
        return std::wstring(strData);
    }
    else {
        // �����ƻ��������ͣ���ԭʼ���ݷ���
        return std::wstring(reinterpret_cast<wchar_t*>(buffer.data()),
            dataSize / sizeof(wchar_t));
    }
}

// ��ȡͼ���������CLSID
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0;  // ����������
    UINT size = 0; // ��������С

    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) {
        return -1;
    }

    Gdiplus::ImageCodecInfo* pImageCodecInfo =
        (Gdiplus::ImageCodecInfo*)(malloc(size));
    if (pImageCodecInfo == NULL) {
        return -1;
    }

    Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);

    for (UINT i = 0; i < num; ++i) {
        if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[i].Clsid;
            free(pImageCodecInfo);
            return i;
        }
    }

    free(pImageCodecInfo);
    return -1;
}

// ��ȡ��ǰʱ����Ϊ�ļ���
std::wstring GetCurrentTimeFileName() {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) %
        1000;

    std::tm now_tm;
    localtime_s(&now_tm, &now_time_t);

    std::wstringstream wss;
    wss << L"C:\\screenshots\\" << std::put_time(&now_tm, L"%Y%m%d_%H%M%S")
        << L"_" << std::setfill(L'0') << std::setw(3) << now_ms.count()
        << L".png";

    return wss.str();
}

// �������沢����ΪPNG�ļ�
bool CaptureDesktopToFile(const std::wstring& filename) {
    // ��ʼ��GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // ��ȡ��Ļ�ߴ�
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // ����λͼ����
    HBITMAP hBitmap = NULL;
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);

    hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    if (hBitmap == NULL) {
        ReleaseDC(NULL, hdcScreen);
        DeleteDC(hdcMem);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return false;
    }

    // ѡ��λͼ���ڴ�DC
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);

    // ������Ļ���ݵ�λͼ
    BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);

    // �ָ�ԭ����λͼ
    SelectObject(hdcMem, hOldBitmap);

    // ����GDI+λͼ����
    Gdiplus::Bitmap* pBitmap = Gdiplus::Bitmap::FromHBITMAP(hBitmap, NULL);

    // ��ȡPNG��������CLSID
    CLSID clsidPng;
    if (GetEncoderClsid(L"image/png", &clsidPng) == -1) {
        delete pBitmap;
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return false;
    }

    // ����Ŀ¼����������ڣ�
    CreateDirectory(L"C:\\screenshots", NULL);

    // ����ΪPNG�ļ�
    Gdiplus::Status status = pBitmap->Save(filename.c_str(), &clsidPng, NULL);

    // ������Դ
    delete pBitmap;
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    Gdiplus::GdiplusShutdown(gdiplusToken);

    return status == Gdiplus::Ok;
}

// �������沢���� PNG �ֽ�����
std::vector<BYTE> CaptureDesktopToBytes() {
    if (!IsCurrentInputDesktop()) {
        handleOpenInputDesktop();
    }
  
    std::vector<BYTE> result;

    // ��ʼ��GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // ��ȡ��Ļ�ߴ�
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // �����豸������
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);

    if (!hBitmap) {
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);
    BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);
    SelectObject(hdcMem, hOldBitmap);

    // ת��Ϊ GDI+ Bitmap
    Gdiplus::Bitmap* pBitmap = Gdiplus::Bitmap::FromHBITMAP(hBitmap, NULL);

    // ��ȡ PNG ������ CLSID
    CLSID clsidPng;
    if (GetEncoderClsid(L"image/png", &clsidPng) != -1) {
        // ���浽 IStream���ڴ�����
        IStream* pStream = NULL;
        if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK) {
            if (pBitmap->Save(pStream, &clsidPng, NULL) == Gdiplus::Ok) {
                // ��ȡ HGLOBAL
                HGLOBAL hGlobal = NULL;
                GetHGlobalFromStream(pStream, &hGlobal);

                // �������ݵ� result
                SIZE_T size = GlobalSize(hGlobal);
                void* pData = GlobalLock(hGlobal);
                if (pData && size > 0) {
                    result.resize(size);
                    memcpy(result.data(), pData, size);
                }
                GlobalUnlock(hGlobal);
            }
            pStream->Release();
        }
    }

    // ����
    delete pBitmap;
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    Gdiplus::GdiplusShutdown(gdiplusToken);

    return result;
}


#include <Windows.h>

// Java KeyEvent �� Windows ��������ӳ�亯��
#include <windows.h>
#include <map>

/**
 * Java KeyEvent keyCode -> Windows VK keyCode
 * �ο�: java.awt.event.KeyEvent / WinUser.h
 */
int MapJavaKeyCodeToWinVK(int javaKeyCode) {
    switch (javaKeyCode) {
        // ===== ���Ƽ� =====
        case 16:  return VK_SHIFT;     // KeyEvent.VK_SHIFT
        case 17:  return VK_CONTROL;   // KeyEvent.VK_CONTROL
        case 18:  return VK_MENU;      // KeyEvent.VK_ALT
        case 20:  return VK_CAPITAL;   // KeyEvent.VK_CAPS_LOCK
        case 9:   return VK_TAB;       // KeyEvent.VK_TAB
        case 10:  return VK_RETURN;    // KeyEvent.VK_ENTER
        case 27:  return VK_ESCAPE;    // KeyEvent.VK_ESCAPE
        case 32:  return VK_SPACE;     // KeyEvent.VK_SPACE
        case 127: return VK_DELETE;    // KeyEvent.VK_DELETE
        case 36:  return VK_HOME;      // KeyEvent.VK_HOME
        case 35:  return VK_END;       // KeyEvent.VK_END
        case 33:  return VK_PRIOR;     // KeyEvent.VK_PAGE_UP
        case 34:  return VK_NEXT;      // KeyEvent.VK_PAGE_DOWN
        case 155: return VK_INSERT;    // KeyEvent.VK_INSERT
        case 8:   return VK_BACK;      // KeyEvent.VK_BACK_SPACE

        // ===== ���ܼ� F1-F12 ===== (Java �� Win ֵһ��)
        case 112: return VK_F1;
        case 113: return VK_F2;
        case 114: return VK_F3;
        case 115: return VK_F4;
        case 116: return VK_F5;
        case 117: return VK_F6;
        case 118: return VK_F7;
        case 119: return VK_F8;
        case 120: return VK_F9;
        case 121: return VK_F10;
        case 122: return VK_F11;
        case 123: return VK_F12;

        // ===== ����� (Java �� Win ֵһ��) =====
        case 37: return VK_LEFT;
        case 38: return VK_UP;
        case 39: return VK_RIGHT;
        case 40: return VK_DOWN;

         // ===== С���� (NumPad) =====
        case 96: return VK_NUMPAD0;
        case 97: return VK_NUMPAD1;
        case 98: return VK_NUMPAD2;
        case 99: return VK_NUMPAD3;
        case 100: return VK_NUMPAD4;
        case 101: return VK_NUMPAD5;
        case 102: return VK_NUMPAD6;
        case 103: return VK_NUMPAD7;
        case 104: return VK_NUMPAD8;
        case 105: return VK_NUMPAD9;
        case 106: return VK_MULTIPLY;
        case 107: return VK_ADD;
        case 109: return VK_SUBTRACT;
        case 110: return VK_DECIMAL;
        case 111: return VK_DIVIDE;


        case 59:  return VK_OEM_1;     // ;:
        case 61:  return VK_OEM_PLUS;  // =
        case 44:  return VK_OEM_COMMA; // ,
        case 45:  return VK_OEM_MINUS; // -
        case 46:  return VK_OEM_PERIOD;// .
        case 47:  return VK_OEM_2;     // /?
        case 192: return VK_OEM_3;     // `~
        case 91:  return VK_OEM_4;     // [{
        case 92:  return VK_OEM_5;     // \|
        case 93:  return VK_OEM_6;     // ]}
        case 222: return VK_OEM_7;     // '"
    default:
        return javaKeyCode; // û������ӳ��ʱֱ�ӷ��أ����ּ�ֵ�� Win/Linux ��ͬ��
    }
}



void SimulateKeyEvent(int keyCode, int pressed) {
    if (!IsCurrentInputDesktop()) {
        handleOpenInputDesktop();
    }

    INPUT input;
    ZeroMemory(&input, sizeof(INPUT));
    input.type = INPUT_KEYBOARD;

    // ӳ�� Win VK
    input.ki.wVk = MapJavaKeyCodeToWinVK(keyCode);

    // ʹ��ɨ���뱣֤������/�����л������Ҳ����Ч
    input.ki.wScan = MapVirtualKey(input.ki.wVk, MAPVK_VK_TO_VSC);

    // KEYEVENTF_SCANCODE ������ϣ�����ĳЩ��������������Ч
    input.ki.dwFlags = KEYEVENTF_SCANCODE;
    if (!pressed) {
        input.ki.dwFlags |= KEYEVENTF_KEYUP;
    }

    input.ki.time = 0;
    input.ki.dwExtraInfo = 0;

    SendInput(1, &input, sizeof(INPUT));
}

void SimulateMouseEvent(int x, int y, int info, int rotations) {
    if (!IsCurrentInputDesktop()) {
        handleOpenInputDesktop();
    }
    INPUT input;
    ZeroMemory(&input, sizeof(INPUT));
    input.type = INPUT_MOUSE;

    // �����һ��
    input.mi.dx = (x * 65536) / GetSystemMetrics(SM_CXSCREEN);
    input.mi.dy = (y * 65536) / GetSystemMetrics(SM_CYSCREEN);
    input.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;

    // ��갴��
    if (info & 0x1) input.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
    if (info & 0x2) input.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
    if (info & 0x4) input.mi.dwFlags |= MOUSEEVENTF_RIGHTDOWN;
    if (info & 0x8) input.mi.dwFlags |= MOUSEEVENTF_RIGHTUP;
    if (info & 0x10) input.mi.dwFlags |= MOUSEEVENTF_MIDDLEDOWN;
    if (info & 0x20) input.mi.dwFlags |= MOUSEEVENTF_MIDDLEUP;

    // ������
    if (info & 0x40) {
        input.mi.dwFlags = MOUSEEVENTF_WHEEL;
        input.mi.mouseData = rotations * 120; // 120 = 1 notch
    }

    SendInput(1, &input, sizeof(INPUT));
}

extern "C" {

    // �жϵ�ǰ�߳��Ƿ�����������
    __declspec(dllexport) BOOL IsCurrentInputDesktopJNA() {
        return IsCurrentInputDesktop();
    }

    // ����������
    __declspec(dllexport) BOOL handleOpenInputDesktopJNA() {
        return handleOpenInputDesktop();
    }

    // �������淵�� PNG �ֽ�����
    __declspec(dllexport) int CaptureDesktopToBytesJNA(BYTE** data, int* size) {
        std::vector<BYTE> bytes = CaptureDesktopToBytes();
        if (bytes.empty()) {
            *data = nullptr;
            *size = 0;
            return 0;
        }

        *size = static_cast<int>(bytes.size());
        *data = (BYTE*)CoTaskMemAlloc(*size); // �� CoTaskMemAlloc �� Java �ͷ�
        memcpy(*data, bytes.data(), *size);
        return 1;
    }

    // �ͷ� CaptureDesktopToBytes ������ڴ�
    __declspec(dllexport) void FreeBytesJNA(BYTE* data) {
        if (data) {
            CoTaskMemFree(data);
        }
    }

    __declspec(dllexport) void SimulateKeyEventJNA(int keyCode, int pressed) {
        SimulateKeyEvent(keyCode, pressed);
    }

    __declspec(dllexport) void SimulateMouseEventJNA(int x, int y, int info, int rotations) {
        SimulateMouseEvent(x, y,info,rotations);
    }
}
// ����ڵ�
int main() {

    // ���ؿ���̨���ڣ�����ǿ���̨����
    // FreeConsole();

    //// ����Ҫ�����ĵط�
    //// std::thread cursorThread(handleLoopGetCursorPos);
    //// cursorThread.detach(); // �����̣߳������ں�̨����

    //// ����Ҫ�����ĵط�
    // std::thread startCaptureThread(startCapture);
    //// startCaptureThread.detach(); // �����̣߳������ں�̨����
    // startCaptureThread.join();

    while (true) {

        if (IsCurrentInputDesktop()) {
            AsyncLogger::GetInstance().log("��ǰ���������");
        }
        else {
            handleOpenInputDesktop();
            AsyncLogger::GetInstance().log("��ǰ����������棡����");
        }

        // ��ȡ��ǰʱ����Ϊ�ļ���
        wstring filename = GetCurrentTimeFileName();

        CaptureDesktopToBytes();
        // �������沢����
        if (CaptureDesktopToFile(filename)) {
            wcout << L"��ͼ�ѱ���: " << filename << endl;
        }
        else {
            wcout << L"��ͼʧ��!" << endl;
        }

        // �ȴ�1��
        Sleep(1000);
    }

    return 1;
}