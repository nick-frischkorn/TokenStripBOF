#pragma once
#include "syscalls.h"

#define ZwAdjustPrivilegesToken NtAdjustPrivilegesToken
__asm__("NtAdjustPrivilegesToken: \n\
	mov rax, gs:[0x60]                                  \n\
NtAdjustPrivilegesToken_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtAdjustPrivilegesToken_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtAdjustPrivilegesToken_Check_10_0_XXXX \n\
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown \n\
NtAdjustPrivilegesToken_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtAdjustPrivilegesToken_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtAdjustPrivilegesToken_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtAdjustPrivilegesToken_SystemCall_6_3_XXXX \n\
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown \n\
NtAdjustPrivilegesToken_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7601 \n\
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown \n\
NtAdjustPrivilegesToken_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19042 \n\
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown \n\
NtAdjustPrivilegesToken_SystemCall_6_1_7600:           \n\
	mov eax, 0x003e \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_6_1_7601:           \n\
	mov eax, 0x003e \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x003f \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0040 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_10240:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_10586:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_14393:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_15063:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_16299:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_17134:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_17763:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_18362:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_18363:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_19041:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_19042:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_Unknown:            \n\
	ret \n\
NtAdjustPrivilegesToken_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwClose NtClose
__asm__("NtClose: \n\
	mov rax, gs:[0x60]                  \n\
NtClose_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtClose_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtClose_Check_10_0_XXXX \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtClose_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtClose_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtClose_SystemCall_6_3_XXXX \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtClose_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtClose_SystemCall_6_1_7601 \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtClose_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtClose_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtClose_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtClose_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtClose_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtClose_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtClose_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtClose_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtClose_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtClose_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtClose_SystemCall_10_0_19042 \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_SystemCall_6_1_7600:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_1_7601:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x000d \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x000e \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_10240:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_10586:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_14393:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_15063:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_16299:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_17134:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_17763:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_18362:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_18363:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_19041:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_19042:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_Unknown:            \n\
	ret \n\
NtClose_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwOpenProcess NtOpenProcess
__asm__("NtOpenProcess: \n\
	mov rax, gs:[0x60]                        \n\
NtOpenProcess_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtOpenProcess_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtOpenProcess_Check_10_0_XXXX \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtOpenProcess_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtOpenProcess_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtOpenProcess_SystemCall_6_3_XXXX \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtOpenProcess_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtOpenProcess_SystemCall_6_1_7601 \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtOpenProcess_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtOpenProcess_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtOpenProcess_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtOpenProcess_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtOpenProcess_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtOpenProcess_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtOpenProcess_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtOpenProcess_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtOpenProcess_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtOpenProcess_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtOpenProcess_SystemCall_10_0_19042 \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_SystemCall_6_1_7600:           \n\
	mov eax, 0x0023 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_1_7601:           \n\
	mov eax, 0x0023 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0024 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0025 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_10240:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_10586:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_14393:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_15063:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_16299:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_17134:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_17763:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_18362:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_18363:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_19041:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_19042:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_Unknown:            \n\
	ret \n\
NtOpenProcess_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwOpenProcessToken NtOpenProcessToken
__asm__("NtOpenProcessToken: \n\
	mov rax, gs:[0x60]                             \n\
NtOpenProcessToken_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtOpenProcessToken_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtOpenProcessToken_Check_10_0_XXXX \n\
	jmp NtOpenProcessToken_SystemCall_Unknown \n\
NtOpenProcessToken_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtOpenProcessToken_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtOpenProcessToken_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtOpenProcessToken_SystemCall_6_3_XXXX \n\
	jmp NtOpenProcessToken_SystemCall_Unknown \n\
NtOpenProcessToken_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtOpenProcessToken_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtOpenProcessToken_SystemCall_6_1_7601 \n\
	jmp NtOpenProcessToken_SystemCall_Unknown \n\
NtOpenProcessToken_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtOpenProcessToken_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtOpenProcessToken_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtOpenProcessToken_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtOpenProcessToken_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtOpenProcessToken_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtOpenProcessToken_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtOpenProcessToken_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtOpenProcessToken_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtOpenProcessToken_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtOpenProcessToken_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtOpenProcessToken_SystemCall_10_0_19042 \n\
	jmp NtOpenProcessToken_SystemCall_Unknown \n\
NtOpenProcessToken_SystemCall_6_1_7600:           \n\
	mov eax, 0x00f9 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_6_1_7601:           \n\
	mov eax, 0x00f9 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x010b \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x010e \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_10240:         \n\
	mov eax, 0x0114 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_10586:         \n\
	mov eax, 0x0117 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_14393:         \n\
	mov eax, 0x0119 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_15063:         \n\
	mov eax, 0x011d \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_16299:         \n\
	mov eax, 0x011f \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_17134:         \n\
	mov eax, 0x0121 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_17763:         \n\
	mov eax, 0x0122 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_18362:         \n\
	mov eax, 0x0123 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_18363:         \n\
	mov eax, 0x0123 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_19041:         \n\
	mov eax, 0x0128 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_19042:         \n\
	mov eax, 0x0128 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_Unknown:            \n\
	ret \n\
NtOpenProcessToken_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwSetInformationToken NtSetInformationToken
__asm__("NtSetInformationToken: \n\
	mov rax, gs:[0x60]                                \n\
NtSetInformationToken_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtSetInformationToken_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtSetInformationToken_Check_10_0_XXXX \n\
	jmp NtSetInformationToken_SystemCall_Unknown \n\
NtSetInformationToken_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtSetInformationToken_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtSetInformationToken_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtSetInformationToken_SystemCall_6_3_XXXX \n\
	jmp NtSetInformationToken_SystemCall_Unknown \n\
NtSetInformationToken_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtSetInformationToken_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtSetInformationToken_SystemCall_6_1_7601 \n\
	jmp NtSetInformationToken_SystemCall_Unknown \n\
NtSetInformationToken_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtSetInformationToken_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtSetInformationToken_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtSetInformationToken_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtSetInformationToken_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtSetInformationToken_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtSetInformationToken_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtSetInformationToken_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtSetInformationToken_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtSetInformationToken_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtSetInformationToken_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtSetInformationToken_SystemCall_10_0_19042 \n\
	jmp NtSetInformationToken_SystemCall_Unknown \n\
NtSetInformationToken_SystemCall_6_1_7600:           \n\
	mov eax, 0x015e \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_6_1_7601:           \n\
	mov eax, 0x015e \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0174 \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0177 \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_10_0_10240:         \n\
	mov eax, 0x017f \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_10_0_10586:         \n\
	mov eax, 0x0182 \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_10_0_14393:         \n\
	mov eax, 0x0188 \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_10_0_15063:         \n\
	mov eax, 0x018e \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_10_0_16299:         \n\
	mov eax, 0x0191 \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_10_0_17134:         \n\
	mov eax, 0x0193 \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_10_0_17763:         \n\
	mov eax, 0x0194 \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_10_0_18362:         \n\
	mov eax, 0x0195 \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_10_0_18363:         \n\
	mov eax, 0x0195 \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_10_0_19041:         \n\
	mov eax, 0x019b \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_10_0_19042:         \n\
	mov eax, 0x019b \n\
	jmp NtSetInformationToken_Epilogue \n\
NtSetInformationToken_SystemCall_Unknown:            \n\
	ret \n\
NtSetInformationToken_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

