.code

NtGdiDdDDICreateAllocation PROC
	mov r10, rcx
	mov eax, 118Ah
	syscall
	ret
NtGdiDdDDICreateAllocation ENDP

END