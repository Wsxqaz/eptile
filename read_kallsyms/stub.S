.macro CALL_COPY_N_ARGS n
.endm

.global KHOOK_STUB_hook_noref
.global KHOOK_STUB_hook_noref_end

KHOOK_STUB_hook_noref:
	sub $(8 * 8), %rsp
	.set i, 0
	.rept 8
		mov ((8 + i + 1) * 8)(%rsp), %rax
		mov %rax, (i * 8)(%rsp)
		.set i, i + 1
	.endr
	movabs $0x7a7a7a7a7a7a7a7a, %rax
	call *%rax
	add $(8 * 8), %rsp
	ret

KHOOK_STUB_hook_noref_end:
	ret

