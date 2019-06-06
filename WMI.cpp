#define _WIN32_DCOM
#define UNICODE
#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")

#include <wincred.h>
#include <strsafe.h>
#include <clocale>


HRESULT hres;
IWbemLocator *pLoc = NULL;
IWbemServices *pSvc = NULL;

// Get the user name and password for the remote computer
CREDUI_INFO cui;
bool useToken = false;
bool useNTLM = true;
wchar_t pszName[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
wchar_t pszPwd[CREDUI_MAX_PASSWORD_LENGTH + 1] = { 0 };
wchar_t pszDomain[CREDUI_MAX_USERNAME_LENGTH + 1];
wchar_t pszUserName[CREDUI_MAX_USERNAME_LENGTH + 1];
wchar_t pszAuthority[CREDUI_MAX_USERNAME_LENGTH + 1];
BOOL fSave;
DWORD dwErr;
COAUTHIDENTITY *userAcct = NULL;
COAUTHIDENTITY authIdent;
IEnumWbemClassObject* pEnumerator = NULL;
IWbemClassObject *pclsObj = NULL;
ULONG uReturn = 0;

int step1()
{
	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		cout << "Failed to initialize COM library. Error code = 0x"
			<< hex << hres << endl;
		return -1;                  // Program has failed.
	}
	return 1;
}

int step2()
{
	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------

	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IDENTIFY,    // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
		);


	if (FAILED(hres))
	{
		cout << "Failed to initialize security. Error code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return -1;                    // Program has failed.
	}
	return 1;
}

int step3()
{
	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------

	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID *)&pLoc);

	if (FAILED(hres))
	{
		cout << "Failed to create IWbemLocator object."
			<< " Err code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return -1;                 // Program has failed.
	}
	return 1;
}

int step4()
{
	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method



	memset(&cui, 0, sizeof(CREDUI_INFO));
	cui.cbSize = sizeof(CREDUI_INFO);
	cui.hwndParent = NULL;
	// Ensure that MessageText and CaptionText identify
	// what credentials to use and which application requires them.
	cui.pszMessageText = TEXT("Press cancel to use process token");
	cui.pszCaptionText = TEXT("Enter Account Information");
	cui.hbmBanner = NULL;
	fSave = FALSE;

	dwErr = CredUIPromptForCredentials(
		&cui,                             // CREDUI_INFO structure
		TEXT(""),                         // Target for credentials
		NULL,                             // Reserved
		0,                                // Reason
		pszName,                          // User name
		CREDUI_MAX_USERNAME_LENGTH + 1,     // Max number for user name
		pszPwd,                           // Password
		CREDUI_MAX_PASSWORD_LENGTH + 1,     // Max number for password
		&fSave,                           // State of save check box
		CREDUI_FLAGS_GENERIC_CREDENTIALS |// flags
		CREDUI_FLAGS_ALWAYS_SHOW_UI |
		CREDUI_FLAGS_DO_NOT_PERSIST);

	if (dwErr == ERROR_CANCELLED)
	{
		useToken = true;
	}
	else if (dwErr)
	{
		cout << "Did not get credentials " << dwErr << endl;
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	// change the computerName strings below to the full computer name
	// of the remote computer
	if (!useNTLM)
	{
		StringCchPrintf(pszAuthority, CREDUI_MAX_USERNAME_LENGTH + 1, L"kERBEROS:%s", L"WIN-NSMSUBK73L2");
	}



	return 1;
}

int step42(WCHAR *space)
{
	// Connect to the remote root\cimv2 namespace
	// and obtain pointer pSvc to make IWbemServices calls.
	//---------------------------------------------------------

	hres = pLoc->ConnectServer(
		_bstr_t(space),
		_bstr_t(useToken ? NULL : pszName),    // User name
		_bstr_t(useToken ? NULL : pszPwd),     // User password
		NULL,                              // Locale             
		NULL,                              // Security flags
		_bstr_t(useNTLM ? NULL : pszAuthority),// Authority        
		NULL,                              // Context object 
		&pSvc                              // IWbemServices proxy
		);

	if (FAILED(hres))
	{
		cout << "Could not connect. Error code = 0x"
			<< hex << hres << endl;
		cout << "Wrong user login\\pass" << endl;
		getchar();
		getchar();
		pLoc->Release();
		CoUninitialize();
		exit(1);
	}

	//wcout << "Connected to " << space <<  " namespace" << endl;

}

int step5()
{
	// step 5: --------------------------------------------------
	// Create COAUTHIDENTITY that can be used for setting security on proxy

	if (!useToken)
	{
		memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
		authIdent.PasswordLength = wcslen(pszPwd);
		authIdent.Password = (USHORT*)pszPwd;

		LPWSTR slash = wcschr(pszName, L'\\');
		if (slash == NULL)
		{
			cout << "Could not create Auth identity. No domain specified\n";
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return 1;               // Program has failed.
		}

		StringCchCopy(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);
		authIdent.User = (USHORT*)pszUserName;
		authIdent.UserLength = wcslen(pszUserName);

		StringCchCopyN(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName, slash - pszName);
		authIdent.Domain = (USHORT*)pszDomain;
		authIdent.DomainLength = slash - pszName;
		authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

		userAcct = &authIdent;

	}
	return 1;
}

int step6()
{

	// Step 6: --------------------------------------------------
	// Set security levels on a WMI connection ------------------

	hres = CoSetProxyBlanket(
		pSvc,                           // Indicates the proxy to set
		RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
		COLE_DEFAULT_PRINCIPAL,         // Server principal name 
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
		userAcct,                       // client identity
		EOAC_NONE                       // proxy capabilities 
		);

	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket. Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
	}
	return 1;
}

int step7(char *class_name)
{
	// Step 7: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----

	// For example, get the name of the operating system

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(class_name),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		cout << "Query for operating system name failed."
			<< " Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return -1;               // Program has failed.
	}

	return 1;
}

int step8()
{
	// Step 8: -------------------------------------------------
	// Secure the enumerator proxy
	hres = CoSetProxyBlanket(
		pEnumerator,                    // Indicates the proxy to set
		RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
		COLE_DEFAULT_PRINCIPAL,         // Server principal name 
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
		userAcct,                       // client identity
		EOAC_NONE                       // proxy capabilities 
		);

	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket on enumerator. Error code = 0x"
			<< hex << hres << endl;
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return -1;               // Program has failed.
	}

	// When you have finished using the credentials,
	// erase them from memory.


	return 1;

}

VARIANT vtProp_tmp;

int step9(WCHAR *szWQL, int flag)
{
	// Step 9: -------------------------------------------------
	// Get the data from the query in step 7 -------------------

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);
		VARIANT vtProp;

		if (0 == uReturn)
		{
			break;
		}

		// Get the value of the Name property
		hr = pclsObj->Get(szWQL, 0, &vtProp, 0, 0);

		memcpy((void*)&vtProp_tmp, (void*)&vtProp, sizeof(vtProp));

		if (flag == 0)wcout << vtProp.bstrVal << endl;
		else if (flag == 1)wcout << vtProp.uintVal << endl;
		VariantClear(&vtProp);

		pclsObj->Release();
		pclsObj = NULL;
	}

	return 1;
}

void cleric()
{
	// Cleanup
	// ========

	SecureZeroMemory(pszName, sizeof(pszName));
	SecureZeroMemory(pszPwd, sizeof(pszPwd));
	SecureZeroMemory(pszUserName, sizeof(pszUserName));
	SecureZeroMemory(pszDomain, sizeof(pszDomain));

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	if (pclsObj)
	{
		pclsObj->Release();
	}

	CoUninitialize();
}

void init()
{
	step1();
	step2();
	step3();
	step4();
}

int cly = 0;

void getit(WCHAR *space, char *class_name, WCHAR *szWQL, int flag)
{
	cly = 1;
	step42(space);
	step5();
	step6();
	step7(class_name);
	step8();
	step9(szWQL, flag);
}

void print_menu()
{
	cout << "1. Installed applications" << endl;
	cout << "2. Firewall" << endl;
	cout << "3. AntiVirus" << endl;
	cout << "4. Antispy" << endl;
	cout << "5. OS serial number" << endl;
	cout << "6. Current time" << endl;
	cout << "7. System drivers:" << endl;
	cout << "8. Name operating system:" << endl;
	cout << "9. Services:" << endl;
	cout << "10. Country code: " << endl;
	cout << "11. Clear and print menu again" << endl;
	cout << "0. Exit" << endl;
}

int __cdecl main(int argc, char **argv)
{
	setlocale(LC_ALL, "Russian");
	init();

	print_menu();

	int select;
	while (1) {
		cout << "\nEnter comm: ";
		cin >> select;
		//Get-WmiObject -namespace root\cimv2 -Class Win32_OperatingSystem      | Select-Object -Property CountryCode


		if (select == 1)
		{
			cout << "Installed applications:" << endl;
			getit(L"\\\\laba\\root\\cimv2", "SELECT * FROM Win32_Product", L"Name", 0);	// 0 - string; 1 - int
		}
		else if (select == 2) {
			cout << "Firewall: ";
			getit(L"\\\\laba\\root\\SecurityCenter2", "SELECT * FROM FirewallProduct", L"displayName", 0);
		}
		else if (select == 3) {
			cout << "AntiVirus: ";
			getit(L"\\\\laba\\root\\SecurityCenter2", "SELECT * FROM AntivirusProduct", L"displayName", 0);
		}
		else if (select == 4) {
			cout << "AntiSpy:" << endl;
			getit(L"\\\\laba\\root\\SecurityCenter2", "SELECT * FROM AntiSpywareProduct", L"displayName", 0);
		}
		else if (select == 5) {
			cout << "Serial number: ";
			getit(L"\\\\laba\\root\\cimv2", "SELECT * FROM Win32_OperatingSystem ", L"SerialNumber", 0);
		}
		else if (select == 6) {
			cout << "Current time(hour:minute:second:year):" << endl;
			getit(L"\\\\laba\\root\\cimv2", "SELECT * FROM Win32_LocalTime", L"Hour", 1);
			getit(L"\\\\laba\\root\\cimv2", "SELECT * FROM Win32_LocalTime", L"Minute", 1);
			getit(L"\\\\laba\\root\\cimv2", "SELECT * FROM Win32_LocalTime", L"Second", 1);
			getit(L"\\\\laba\\root\\cimv2", "SELECT * FROM Win32_LocalTime", L"year", 1);
		}
		else if (select == 7) {
			cout << "System drivers:" << endl;
			getit(L"\\\\laba\\root\\cimv2", "SELECT * FROM Win32_SystemDriver ", L"Name", 0);
		}
		else if (select == 8) {
			cout << "Name operating system:" << endl;
			getit(L"\\\\laba\\root\\cimv2", "SELECT * FROM Win32_OperatingSystem", L"Name", 0);
		}
		else if (select == 9) {
			cout << "Name:" << endl;
			getit(L"\\\\laba\\root\\cimv2", "SELECT * FROM Win32_Service ", L"Name", 0);
		}
		else if (select == 10) {
			cout << "Country code: ";
			getit(L"\\\\laba\\root\\cimv2", "SELECT * FROM Win32_OperatingSystem ", L"CountryCode", 0); //
		}
		else if (select == 11) {
			system("cls");
			print_menu();
		}
		else if (select == 0) {
			if (cly)cleric();
			exit(1);

		}
		else {
			cout << "error" << endl;
		}
	}
	cleric();
	return 1;
}