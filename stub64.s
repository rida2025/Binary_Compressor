BITS 64
global _start

_start:
    push rax
    push rdi
    push rsi
    push rdx
    push rcx
    push r11
    pushfq 

    call msg

    popfq
    pop r11
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rax

    mov rax, 9 ;nmap number
    xor rdi, rdi
    mov rsi, 0xBBBBBBBBBBBBBBB1 ; .text original size
    mov rdx, 3
    mov r10, 0x22
    mov r8, -1
    xor r9, r9
    syscall

    mov r12, rax
    mov r15, rax
    
    lea rdi, [rel _start]
    mov r10, 0xAAAAAAAAAAAAAAA1 ; .text address
    sub rdi, r10
    mov rcx, 0xEEEEEEEEEEEEEEE1 ; .text compressed size
    call decompress

    lea rdi, [rel _start]
    mov r10, 0xAAAAAAAAAAAAAAA1
    sub rdi, r10
    mov rcx, 0xBBBBBBBBBBBBBBB1

    mov rsi, r15
    rep movsb ;copy everything to the original location

    lea rax, [rel _start]
    mov r10, 0xCCCCCCCCCCCCCCCC ; distance between oep and stub
    sub rax, r10
    push rax
    ret

msg:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel decompres]
    mov rdx, 24
    syscall
    ret

decompress:
    test rcx, rcx
    jz .done
    mov r14, rdi
    add r14, rcx

.loop:
    cmp rdi, r14
    jge .done

    mov bl, [rdi]
    inc rdi
    mov dl, 8
    
.loop2:
    test bl, 1
    jnz .literal

    movzx r8d, byte [rdi]
    shl r8d, 8
    movzx r9d, byte [rdi+1]
    or r8d, r9d
    add rdi, 2

    mov r9d, r8d
    shr r9d, 4
    mov r10d, r8d
    and r10d, 0xF
    add r10d, 3
    mov r11d, r10d
    mov r13, r12
    sub r13, r9
    
.copy:
    mov al, [r13]
    inc r13
    mov [r12], al
    inc r12
    dec r11d
    jnz .copy
    jmp .next
    
.literal:
    mov al, [rdi]
    inc rdi
    mov [r12], al
    inc r12
    
.next:
    shr bl, 1
    dec dl
    jnz .loop2
    jmp .loop
.done:
    ret
    
decompres: db "decompresing the binary", 10