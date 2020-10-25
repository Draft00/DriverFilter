#ifndef USER_HEADER_H
#define USER_HEADER_H

#include <iostream>
#include <windows.h>
#include <winioctl.h>
#include <fstream>
#include <string>
#include <vector>

#define DEVICE_SEND CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_WRITE_DATA)//2 22:30
#define DEVICE_REC CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_READ_DATA)//2 23:00
#define MAX_LENGTH 500

int Init_update(void);
int Open_device(void);
int Close_device(void);
int Add_record(void);
void Show_record(void);
int Delete_record(void);
void Set_notify(void);

#endif // !USER_HEADER_H
