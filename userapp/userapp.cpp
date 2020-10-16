#include "userHeader.h"

HANDLE devicehandle = NULL;

int main()
{
	std::ifstream config_file_read;
	config_file_read.open("config.csv");

	if (!config_file_read)
	{
		std::ofstream config_file_write;
		config_file_write.open("config.csv");
		config_file_write.close();
	}
	else {
		config_file_read.close();
	}

	while (1)
	{
		std::cout << "Choose command:" << std::endl;
		printf("\n1. Open device;\n2. Close device\n3. Send data\n4. Receive data\n5. Add record\n6. Delete record\n7. Show records\n8. Exit\n");
		int choice = 0;
		std::cin >> choice;
		switch (choice)
		{
		case 1: {
			if (!Open_device())
				return 0;
			break;
		}
		case 2: {
			Close_device();
			break;
		}
		case 3:
		{
			Init_update();
		}
		default:
		{
			std::cout << "Unknown connad." << std::endl;
			break;
		}
		}
	}

	return 1;
}

int Init_update(void)
{
	WCHAR message[] = L"update";
	ULONG returnlength = 0;
	if (devicehandle != INVALID_HANDLE_VALUE && devicehandle != NULL)
	{
		if (!DeviceIoControl(devicehandle, DEVICE_SEND, message, (wcslen(message) + 1) * 2, NULL, 0, &returnlength, 0)) {
			std::cout << "Fail. Init_update:DeviceIoControl(): error" << std::endl;
			return 0;
		}
		else {
			std::cout << "Ok! Send " << returnlength << " bytes " << std::endl;
		}
	}
	return 1;
}

int Open_device(void)
{
	devicehandle = CreateFile(L"\\\\.\\Myfltlink", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	if (devicehandle == INVALID_HANDLE_VALUE)
	{
		std::cout << "Fail. Open_Device:CreateFile(): Invalid Handle Value" << std::endl;
		return 0;
	}
	std::cout << "Ok! Open_Device:CreateFile(): valid value" << std::endl;
	return 1;
}

int Close_device(void)
{
	if (devicehandle != INVALID_HANDLE_VALUE && devicehandle != NULL)
	{
		CloseHandle(devicehandle);
		std::cout << "Ok! Open_Device:CloseHandle()" << std::endl;
		return 1;
	}
	return 0;
}