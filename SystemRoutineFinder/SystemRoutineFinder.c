
#include<ntifs.h>
#include"header.h"
//����GetZwRoutineAddressByName ����

extern PVOID GetExportedRoutineAddressByName(const char* RoutineName) {
	//��RoutineNameתΪPANSI_STRING����
	ANSI_STRING RoutineNameAnsi;
	RtlInitAnsiString(&RoutineNameAnsi, RoutineName);
	return (PVOID)GetZwRoutineAddressByName(&RoutineNameAnsi);
}

