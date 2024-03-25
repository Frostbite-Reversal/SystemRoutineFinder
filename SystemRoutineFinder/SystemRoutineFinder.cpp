
#include<ntifs.h>
#include"header.h"
//����GetZwRoutineAddressByName ����

EXTERN_C PVOID GetExportedRoutineAddressByName(const char* RoutineName) {
	//��RoutineNameתΪPANSI_STRING����
	ANSI_STRING RoutineNameAnsi;
	RtlInitAnsiString(&RoutineNameAnsi, RoutineName);
	return (PVOID)kernel::GetZwRoutineAddressByName(&RoutineNameAnsi);
}

