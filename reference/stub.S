.macro CALL_COPY_N_ARGS n
	sub $(\n * 8), %rsp
	.set i, 0
	.rept \n
		mov ((\n + i + 1) * 8)(%rsp), %rax
		mov %rax, (i * 8)(%rsp)
		.set i, i + 1
	.endr
	movabs $0x7a7a7a7a7a7a7a7a, %rax
	call *%rax
	add $(\n * 8), %rsp
.endm

.global KHOOK_STUB_hook_noref
.global KHOOK_STUB_hook_noref_end

KHOOK_STUB_hook_noref:
	CALL_COPY_N_ARGS 8
	ret

KHOOK_STUB_hook_noref_end:
	ret

