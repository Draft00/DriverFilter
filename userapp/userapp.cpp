#include "userHeader.h"

HANDLE devicehandle = NULL;
int count_record = 0;

#define CONF_FILE_PATH "config.csv"
int main()
{
	std::ifstream config_file_read;
	config_file_read.open(CONF_FILE_PATH);

	if (!config_file_read)
	{
		std::ofstream config_file_write;
		config_file_write.open(CONF_FILE_PATH);
		config_file_write.close();
	}
	else {
		config_file_read.close();
	}

	std::cout << "Choose command:" << std::endl;
	printf("\n1. Open device;\n2. Close device\n3. Add record\n4. Delete record\n5. Show records\n6. Init update\n7. Exit\n8. Notify\n");
	while (1)
	{

		std::cout << "Your choice: ";
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
		case 3: {
			Add_record();
			break;
		}
		case 4: {
			Delete_record();
			break;
		}
		case 5: {
			Show_record();
			break;
		}
		case 6: {
			Init_update();
			break;
		}
		case 7: {
			Close_device();
			return 1;
			break;
		}
		case 8:{
			Set_notify();
			break;
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
void Set_notify(void)
{
	int num = 0;
	WCHAR message1[] = L"setnotify", message2[] = L"removenotify";
	ULONG returnlength = 0;
	std::cout << "Enter 1 to Set notify. Enter 0 to Remove: ";
	std::cin >> num;
	if (devicehandle != INVALID_HANDLE_VALUE && devicehandle != NULL)
	{
		if (num == 0)
		{
			if (!DeviceIoControl(devicehandle, DEVICE_SEND, message2, (wcslen(message2) + 1) * 2, NULL, 0, &returnlength, 0)) {
				std::cout << "Fail. Set_Notify:DeviceIoControl(): error" << std::endl;
			}

		}
		else if (num == 1)
		{
			if (!DeviceIoControl(devicehandle, DEVICE_SEND, message1, (wcslen(message1) + 1) * 2, NULL, 0, &returnlength, 0)) {
				std::cout << "Fail. Set_Notify:DeviceIoControl(): error" << std::endl;
			}
		}
	}
	else {
		std::cout << "Fail. Set_notify: handle = NULL" << std::endl;
	}
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
		return 1;
	}
	std::cout << "Fail. Init_update: handle = NULL" << std::endl;
	return 0;
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

int Add_record(void)
{
	int flag = 0;
	std::string FilePath = "", IntLvl = "";
	std::cout << "Enter 0 to add subj. or 1 to add obj.: ";
	std::cin >> flag;
	std::cout << "Enter filepath w/out Dick:\\. Ex. for \"C:\\Users\\Sergey\\Desktop\\file1.txt\" - \"Users\\Sergey\\Desktop\\file1.txt\": ";
	std::cin >> FilePath; 
	std::cout << "\nEnter IntLvl(1 2 3 4 5): ";
	std::cin >> IntLvl;

	std::ofstream file_config;
	file_config.open(CONF_FILE_PATH, std::ios_base::app);
	file_config << "\\Device\\HarddiskVolume2\\" << FilePath << "," << flag << "," << IntLvl  << std::endl; 
	file_config.close();
	std::cout << "Success. Don't forget InitUpdate!\n";
	++count_record;
	return 1;
}

int Delete_record(void)
{
	int num;
	std::vector<std::string> vec;
	std::ifstream file_config(CONF_FILE_PATH);
	if (!file_config.is_open())
	{
		std::cout << "Failed open file" << std::endl;
		return 0;
	}

	std::string record;
	std::cout << "\nEnter number of record: ";
	std::cin >> num;

	if (num < 1 || num > count_record)
	{
		std::cout << "Incorrect number" << std::endl;
		return 0;
	}

	for (int i = 0; i < count_record; i++)
	{
		std::getline(file_config, record);
		vec.push_back(record);
	}
	file_config.close();
	
	vec.erase(vec.begin() + (num-1));
	count_record = vec.size();
	std::ofstream file_config_wr(CONF_FILE_PATH);
	//std::copy(vec.begin(), vec.end(), std::ostream_iterator<std::wstring, wchar_t>(file_config_wr, L"\n"));
	std::copy(vec.begin(), vec.end(),
		std::ostream_iterator<std::string>(file_config_wr, "\n"));
	file_config_wr.close();
	std::cout << "\n Success. Don't forget InitUpdate!\n";
	return 1;
}


void Show_record(void)
{
	std::string record;
	std::ifstream file_config(CONF_FILE_PATH);
	int num = 0;

	while (std::getline(file_config, record))
	{
		std::cout << ++num << ". " << record << std::endl;
	}
	count_record = num;
	file_config.close();
}