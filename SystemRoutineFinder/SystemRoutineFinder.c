
#include<ntifs.h>
#include"header.h"
//导出GetZwRoutineAddressByName 函数

extern PVOID GetExportedRoutineAddressByName(const char* RoutineName) {
	//将RoutineName转为PANSI_STRING类型
	ANSI_STRING RoutineNameAnsi;
	RtlInitAnsiString(&RoutineNameAnsi, RoutineName);
	return (PVOID)GetZwRoutineAddressByName(&RoutineNameAnsi);
}

