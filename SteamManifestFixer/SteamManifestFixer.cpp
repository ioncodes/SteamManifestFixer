#include "SteamManifestFixer.h"

uint32_t GetProcessIdByName(std::string processName)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &entry))
	{
		while (Process32Next(snapshot, &entry))
		{
			if (processName.compare(entry.szExeFile) == 0)
			{
				return static_cast<uint32_t>(entry.th32ProcessID);
			}
		}
	}
	
	return -1;
}

HMODULE GetHandleForModule(HANDLE processHandle, std::string targetModule)
{
	HMODULE moduleHandles[1024];
	DWORD cbNeeded;
	if (EnumProcessModules(
		processHandle,
		moduleHandles,
		sizeof(moduleHandles),
		&cbNeeded))
	{
		for (HMODULE moduleHandle : moduleHandles)
		{
			TCHAR moduleName[MAX_PATH];
			if (GetModuleFileNameEx(
				processHandle,
				moduleHandle,
				moduleName,
				sizeof(moduleName) / sizeof(TCHAR)))
			{
				if (std::string(moduleName).find(targetModule) != std::string::npos)
				{
					return moduleHandle;
				}
			}
		}
	}

	return nullptr;
}

uint32_t GetModuleSize(HANDLE processHandle, HMODULE moduleHandle)
{
	MODULEINFO moduleInfo = {};
	if (GetModuleInformation(
		processHandle,
		moduleHandle,
		&moduleInfo,
		sizeof(MODULEINFO)))
	{
		return moduleInfo.SizeOfImage;
	}
	
	return -1;
}

uint32_t GetPatchAddress(HANDLE processHandle, uint32_t address, uint32_t size)
{
	uint8_t* buffer = (uint8_t*)malloc(size);
	SIZE_T bytesRead;
	if (ReadProcessMemory(
		processHandle,
		(LPCVOID)address,
		buffer,
		size,
		&bytesRead))
	{
		std::vector<uint8_t> egg = {
			0x84, 0xC0, 
			0x0F, 0x85, 0x2E, 0xFF, 0xFF, 0xFF	
		};

		std::vector<uint8_t> image(buffer, buffer + bytesRead);
		free(buffer);

		auto it = std::search(
			image.begin(), image.end(),
			egg.begin(), egg.end());
		if (it != image.end())
		{
			uint32_t offset = it - image.begin();
			return address + offset + 2;
		}
	}
	return -1;
}

bool WritePatch(HANDLE processHandle, uint32_t imageBase, uint32_t imageSize, uint32_t patchAddress)
{
	DWORD oldProtection;
	if (VirtualProtectEx(
		processHandle,
		(void*)imageBase,
		imageSize,
		PAGE_EXECUTE_READWRITE,
		&oldProtection))
	{
		std::vector<uint8_t> patch = {
			0x0F, 0x84, 0x2E, 0xFF, 0xFF, 0xFF
		};

		SIZE_T bytesWritten;
		if (WriteProcessMemory(
			processHandle,
			(void*)patchAddress,
			std::data(patch),
			patch.size(),
			&bytesWritten))
		{
			return true;
		}
	}

	return false;
}

int main()
{
	auto processId = GetProcessIdByName("steam.exe");
	auto processHandle = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		processId);
	auto moduleHandle = GetHandleForModule(
		processHandle, 
		"steamclient.dll");
	auto moduleSize = GetModuleSize(
		processHandle, 
		moduleHandle);
	std::cout 
		<< "steamclient.dll @ " 
		<< std::hex
		<< reinterpret_cast<uint32_t>(moduleHandle)
		<< " -> "
		<< std::hex
		<< reinterpret_cast<uint32_t>(moduleHandle) + moduleSize
		<< std::endl;
	auto patchAddress = GetPatchAddress(
		processHandle, 
		reinterpret_cast<uint32_t>(moduleHandle),
		moduleSize);
	std::cout
		<< "instruction @ "
		<< std::hex
		<< patchAddress
		<< std::endl;
	if (WritePatch(
		processHandle,
		reinterpret_cast<uint32_t>(moduleHandle),
		moduleSize,
		patchAddress))
	{
		std::cout << "successfully patched!" << std::endl;
	}
	else
	{
		std::cout << "something failed!" << std::endl;
	}
	std::getchar();
	return 0;
}
