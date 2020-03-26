#pragma once

#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <vector>
#include <algorithm>

uint32_t GetProcessIdByName(const std::string processName);
HMODULE GetHandleForModule(HANDLE processHandle, const std::string targetModule);
uint32_t GetModuleSize(HANDLE processHandle, HMODULE moduleHandle);
uint32_t GetPatchAddress(HANDLE processHandle, uint32_t address, uint32_t size);
bool WritePatch(HANDLE processHandle, uint32_t imageBase, uint32_t imageSize, uint32_t patchAddress);
