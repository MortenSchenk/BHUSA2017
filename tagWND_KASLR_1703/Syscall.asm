.code

NtUserDefSetText PROC
	mov r10, rcx
	mov eax, 107Fh
	syscall
	ret
NtUserDefSetText ENDP

END