#define WIN32_LEAN_AND_MEAN // 排除无关的 Windows 头文件
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <Windows.h>

#include <objidl.h> // 必须放在gdiplus.h之前

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


#pragma comment(lib, "ws2_32.lib")   // Winsock基础库（必须第一个）
#pragma comment(lib, "iphlpapi.lib") // 依赖Winsock类型
#pragma comment(lib, "Wtsapi32.lib") // 远程桌面服务
#pragma comment(lib, "Userenv.lib")  // 用户环境管理
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "ole32.lib")

using namespace Gdiplus;
using namespace std;

int httpServerPort = 22200;

std::wstring g_ServiceName = L"MyBilldDeskService";
std::wstring g_AppName = L"BilldDesk";
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
    // 获取单例实例
    static AsyncLogger& GetInstance() {
        static AsyncLogger instance(g_logPath);
        return instance;
    }

    // 可变参数模板版本
    template <typename... Args> void log(Args &&...args) {
        std::string formatted_entry = formatEntry(std::forward<Args>(args)...);
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_queue.push(std::move(formatted_entry));
        }
        m_cond.notify_one();
    }

private:
    // 私有构造（单例模式）
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

    // 递归终止条件
    void formatHelper(std::ostringstream& oss) {}

    // 递归展开参数包
    template <typename T, typename... Args>
    void formatHelper(std::ostringstream& oss, T&& first, Args &&...rest) {
        oss << std::forward<T>(first);
        if (sizeof...(rest) != 0) {
            oss << " "; // 参数间用空格分隔
        }
        formatHelper(oss, std::forward<Args>(rest)...);
    }

    // 格式化参数为字符串
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
        localtime_s(&tm_buffer, &in_time_t); // 使用安全的localtime_s替代localtime

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

// wchar_t转std::string
std::string wchar_to_string(const wchar_t* wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

// std::wstring转std::string
std::string wstring_to_string(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

// 辅助函数：UTF-8 string → wstring
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
        return FALSE;  // 添加返回FALSE
    }
    //AsyncLogger::GetInstance().log("SetThreadDesktop OK");
    return TRUE;  // 添加返回TRUE
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
            AsyncLogger::GetInstance().log("当前是输入界面");
        }
        else {
            g_isLock = true;
            AsyncLogger::GetInstance().log("当前不是输入界面");
        }

        // POINT pos;
        // if (GetCursorPos(&pos) != 0) {
        //   g_isLock = false;
        //   AsyncLogger::GetInstance().log("当前不是锁屏");
        // } else {
        //   g_isLock = true;
        //   AsyncLogger::GetInstance().log("当前是锁屏！！！",
        //                                  std::to_string(GetLastError()));
        // }

        Sleep(900);
    }
}

// 写入注册表值（字符串）
bool WriteStringToRegistry(const std::string& valueNameUTF8,
    const std::string& strValueUTF8) {
    HKEY hKey;
    LONG result;

    // 1. 转换所有字符串为UTF-16
    std::wstring valueName = UTF8ToWide(valueNameUTF8);
    std::wstring strValue = UTF8ToWide(strValueUTF8);

    // 2. 打开注册表键
    result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, g_regPath.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey,
        nullptr);

    if (result != ERROR_SUCCESS) {
        return false;
    }

    // 3. 写入值（REG_SZ类型）
    result = RegSetValueExW(hKey,
        valueName.c_str(), // 转换后的宽字符名称
        0, REG_SZ,
        reinterpret_cast<const BYTE*>(strValue.c_str()),
        (strValue.size() + 1) * sizeof(wchar_t) // 包含终止符
    );

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

// 获取注册表值（字符串）
std::wstring ReadStringFromRegistry(const std::wstring& valueName) {
    HKEY hKey;
    LONG result;

    // 1. 打开注册表键
    result =
        RegOpenKeyEx(HKEY_LOCAL_MACHINE, g_regPath.c_str(), 0, KEY_READ, &hKey);

    if (result != ERROR_SUCCESS) {
        return L"";
    }

    // 2. 获取值类型和大小
    DWORD dataType = 0;
    DWORD dataSize = 0;
    result = RegQueryValueEx(hKey, valueName.c_str(), nullptr,
        &dataType, // 新增：获取数据类型
        nullptr, &dataSize);

    if (result != ERROR_SUCCESS || dataSize == 0) {
        RegCloseKey(hKey);
        return L"";
    }

    // 3. 读取原始数据
    std::vector<BYTE> buffer(dataSize);
    result = RegQueryValueEx(hKey, valueName.c_str(), nullptr, &dataType,
        buffer.data(), &dataSize);

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        return L"";
    }

    // 4. 根据数据类型处理
    if (dataType == REG_SZ || dataType == REG_EXPAND_SZ) {
        // 字符串类型：移除系统自动添加的终止符（仅当是真实终止符时）
        wchar_t* strData = reinterpret_cast<wchar_t*>(buffer.data());
        size_t len = dataSize / sizeof(wchar_t);
        if (len > 0 && strData[len - 1] == L'\0') {
            len--;
        }
        return std::wstring(strData, len);
    }
    else if (dataType == REG_MULTI_SZ) {
        // 多字符串类型（多个\0结尾的字符串）
        // 示例处理：取第一个字符串
        wchar_t* strData = reinterpret_cast<wchar_t*>(buffer.data());
        return std::wstring(strData);
    }
    else {
        // 二进制或其他类型：按原始数据返回
        return std::wstring(reinterpret_cast<wchar_t*>(buffer.data()),
            dataSize / sizeof(wchar_t));
    }
}

// 获取图像编码器的CLSID
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0;  // 编码器数量
    UINT size = 0; // 编码器大小

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

// 获取当前时间作为文件名
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

// 捕获桌面并保存为PNG文件
bool CaptureDesktopToFile(const std::wstring& filename) {
    // 初始化GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // 获取屏幕尺寸
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // 创建位图对象
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

    // 选择位图到内存DC
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);

    // 复制屏幕内容到位图
    BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);

    // 恢复原来的位图
    SelectObject(hdcMem, hOldBitmap);

    // 创建GDI+位图对象
    Gdiplus::Bitmap* pBitmap = Gdiplus::Bitmap::FromHBITMAP(hBitmap, NULL);

    // 获取PNG编码器的CLSID
    CLSID clsidPng;
    if (GetEncoderClsid(L"image/png", &clsidPng) == -1) {
        delete pBitmap;
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return false;
    }

    // 创建目录（如果不存在）
    CreateDirectory(L"C:\\screenshots", NULL);

    // 保存为PNG文件
    Gdiplus::Status status = pBitmap->Save(filename.c_str(), &clsidPng, NULL);

    // 清理资源
    delete pBitmap;
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    Gdiplus::GdiplusShutdown(gdiplusToken);

    return status == Gdiplus::Ok;
}

// 捕获桌面并返回 PNG 字节数组
std::vector<BYTE> CaptureDesktopToBytes() {
    if (!IsCurrentInputDesktop()) {
        handleOpenInputDesktop();
    }
  
    std::vector<BYTE> result;

    // 初始化GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // 获取屏幕尺寸
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // 创建设备上下文
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

    // 转换为 GDI+ Bitmap
    Gdiplus::Bitmap* pBitmap = Gdiplus::Bitmap::FromHBITMAP(hBitmap, NULL);

    // 获取 PNG 编码器 CLSID
    CLSID clsidPng;
    if (GetEncoderClsid(L"image/png", &clsidPng) != -1) {
        // 保存到 IStream（内存流）
        IStream* pStream = NULL;
        if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK) {
            if (pBitmap->Save(pStream, &clsidPng, NULL) == Gdiplus::Ok) {
                // 获取 HGLOBAL
                HGLOBAL hGlobal = NULL;
                GetHGlobalFromStream(pStream, &hGlobal);

                // 复制数据到 result
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

    // 清理
    delete pBitmap;
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    Gdiplus::GdiplusShutdown(gdiplusToken);

    return result;
}


#include <Windows.h>

// Java KeyEvent 到 Windows 虚拟键码的映射函数
#include <windows.h>
#include <map>

/**
 * Java KeyEvent keyCode -> Windows VK keyCode
 * 参考: java.awt.event.KeyEvent / WinUser.h
 */
int MapJavaKeyCodeToWinVK(int javaKeyCode) {
    switch (javaKeyCode) {
    // ===== 功能键 F1-F12 =====
    case 0x70: return VK_F1;
    case 0x71: return VK_F2;
    case 0x72: return VK_F3;
    case 0x73: return VK_F4;
    case 0x74: return VK_F5;
    case 0x75: return VK_F6;
    case 0x76: return VK_F7;
    case 0x77: return VK_F8;
    case 0x78: return VK_F9;
    case 0x79: return VK_F10;
    case 0x7A: return VK_F11;
    case 0x7B: return VK_F12;

     // ===== 方向键 =====
    case 0x25: return VK_LEFT;
    case 0x26: return VK_UP;
    case 0x27: return VK_RIGHT;
    case 0x28: return VK_DOWN;

        // ===== 控制键 =====
    case 0x10: return VK_SHIFT;   // KeyEvent.VK_SHIFT
    case 0x11: return VK_CONTROL; // KeyEvent.VK_CONTROL
    case 0x12: return VK_MENU;    // KeyEvent.VK_ALT
    case 0x14: return VK_CAPITAL; // CapsLock
    case 0x09: return VK_TAB;
    case 0x0D: return VK_RETURN;
    case 0x1B: return VK_ESCAPE;
    case 0x20: return VK_SPACE;
    case 0x2E: return VK_DELETE;
    case 0x24: return VK_HOME;
    case 0x23: return VK_END;
    case 0x21: return VK_PRIOR;   // PageUp
    case 0x22: return VK_NEXT;    // PageDown
    case 0x2D: return VK_INSERT;
    case 0x08: return VK_BACK;

        // ===== 小键盘 (NumPad) =====
    case 0x60: return VK_NUMPAD0;
    case 0x61: return VK_NUMPAD1;
    case 0x62: return VK_NUMPAD2;
    case 0x63: return VK_NUMPAD3;
    case 0x64: return VK_NUMPAD4;
    case 0x65: return VK_NUMPAD5;
    case 0x66: return VK_NUMPAD6;
    case 0x67: return VK_NUMPAD7;
    case 0x68: return VK_NUMPAD8;
    case 0x69: return VK_NUMPAD9;
    case 0x6A: return VK_MULTIPLY;
    case 0x6B: return VK_ADD;
    case 0x6D: return VK_SUBTRACT;
    case 0x6E: return VK_DECIMAL;
    case 0x6F: return VK_DIVIDE;

        // ===== 符号键（常用）=====
    case 0xBA: return VK_OEM_1;   // ;:
    case 0xBB: return VK_OEM_PLUS;  // +
    case 0xBC: return VK_OEM_COMMA; // ,
    case 0xBD: return VK_OEM_MINUS; // -
    case 0xBE: return VK_OEM_PERIOD;// .
    case 0xBF: return VK_OEM_2;   // /?
    case 0xC0: return VK_OEM_3;   // `~
    case 0xDB: return VK_OEM_4;   // [{
    case 0xDC: return VK_OEM_5;   // \|
    case 0xDD: return VK_OEM_6;   // ]}
    case 0xDE: return VK_OEM_7;   // '"

    default:
        return javaKeyCode; // 没有特殊映射时直接返回（部分键值在 Win/Linux 相同）
    }
}



void SimulateKeyEvent(int keyCode, int pressed) {
    if (!IsCurrentInputDesktop()) {
        handleOpenInputDesktop();
    }

    INPUT input;
    ZeroMemory(&input, sizeof(INPUT));
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = MapJavaKeyCodeToWinVK(keyCode);  // 虚拟键码

    if (!pressed) {
        input.ki.dwFlags = KEYEVENTF_KEYUP;  // 抬起
    }

    SendInput(1, &input, sizeof(INPUT));
}

void SimulateMouseEvent(int x, int y, int info, int rotations) {
    INPUT input;
    ZeroMemory(&input, sizeof(INPUT));
    input.type = INPUT_MOUSE;

    // 坐标归一化
    input.mi.dx = (x * 65536) / GetSystemMetrics(SM_CXSCREEN);
    input.mi.dy = (y * 65536) / GetSystemMetrics(SM_CYSCREEN);
    input.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;

    // 鼠标按键
    if (info & 0x1) input.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
    if (info & 0x2) input.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
    if (info & 0x4) input.mi.dwFlags |= MOUSEEVENTF_RIGHTDOWN;
    if (info & 0x8) input.mi.dwFlags |= MOUSEEVENTF_RIGHTUP;
    if (info & 0x10) input.mi.dwFlags |= MOUSEEVENTF_MIDDLEDOWN;
    if (info & 0x20) input.mi.dwFlags |= MOUSEEVENTF_MIDDLEUP;

    // 鼠标滚轮
    if (info & 0x40) {
        input.mi.dwFlags = MOUSEEVENTF_WHEEL;
        input.mi.mouseData = rotations * 120; // 120 = 1 notch
    }

    SendInput(1, &input, sizeof(INPUT));
}

extern "C" {

    // 判断当前线程是否在输入桌面
    __declspec(dllexport) BOOL IsCurrentInputDesktopJNA() {
        return IsCurrentInputDesktop();
    }

    // 打开输入桌面
    __declspec(dllexport) BOOL handleOpenInputDesktopJNA() {
        return handleOpenInputDesktop();
    }

    // 捕获桌面返回 PNG 字节数组
    __declspec(dllexport) int CaptureDesktopToBytesJNA(BYTE** data, int* size) {
        std::vector<BYTE> bytes = CaptureDesktopToBytes();
        if (bytes.empty()) {
            *data = nullptr;
            *size = 0;
            return 0;
        }

        *size = static_cast<int>(bytes.size());
        *data = (BYTE*)CoTaskMemAlloc(*size); // 用 CoTaskMemAlloc 给 Java 释放
        memcpy(*data, bytes.data(), *size);
        return 1;
    }

    // 释放 CaptureDesktopToBytes 分配的内存
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
// 主入口点
int main() {

    // 隐藏控制台窗口（如果是控制台程序）
    // FreeConsole();

    //// 在需要启动的地方
    //// std::thread cursorThread(handleLoopGetCursorPos);
    //// cursorThread.detach(); // 分离线程，让它在后台运行

    //// 在需要启动的地方
    // std::thread startCaptureThread(startCapture);
    //// startCaptureThread.detach(); // 分离线程，让它在后台运行
    // startCaptureThread.join();

    while (true) {

        if (IsCurrentInputDesktop()) {
            AsyncLogger::GetInstance().log("当前是输入界面");
        }
        else {
            handleOpenInputDesktop();
            AsyncLogger::GetInstance().log("当前不是输入界面！！！");
        }

        // 获取当前时间作为文件名
        wstring filename = GetCurrentTimeFileName();

        CaptureDesktopToBytes();
        // 捕获桌面并保存
        if (CaptureDesktopToFile(filename)) {
            wcout << L"截图已保存: " << filename << endl;
        }
        else {
            wcout << L"截图失败!" << endl;
        }

        // 等待1秒
        Sleep(1000);
    }

    return 1;
}