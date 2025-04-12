---
layout: post
title: X64 Linux Shellcode Injection
date: 2025-04-12
categories: ["linux", "malware"]
tags: ["linux", "malware"]
---


*This blog won't show you how you can write shellcode in x64 linux systems.*


# Shellcode Injection

It's kinda technique for hackers that allows them to gain access or doing something. There are a few techniques to executing shellcode. In this demo, I will show you only one technique. Before doing anything, I have to say something about that topic. I haven't seen this method in internet, I just found it by trying somethings. That does not mean this technique belongs to me. In my opinion this technique better than executing shellcode in stack.

Most of linux shellcode injection resources will show you holding shellcode in stack and then create a function pointer and assign your shellcode memory address to that function pointer. For this method you should use `-fno-stack-protector`, `-no-pie` or `-z execstack` flags for GCC.

I used a shellcode that prints "damn it" string to screen. I have written this myself, but I will share it the source code. Now let me explain how it works. In this demo, I'm gonna create a memory region by using `mmap` syscall then will load our shellcode into that memory region by using `memcpy`. Before creating a function pointer for our memory region, you can change the memory region's protection value by using `mprotect`. The last thing is executing it. You can execute it without using any syscall but if you want to execute it as a child process you should use `clone` syscall. These syscalls are accessible through of some header files.

*If you use clone syscall to execute your shellcode, it will create a child process and the child process pid will be 4091, if it's 4090.*

Now this is the shellcode source code and I'm gonna show you how you can compile it.

```
bits 64

section .text
global _start


_start:
	xor r12, r12
	push r12
	mov r12, 0x0A7469206E6D6164
	push r12

	lea rsi, [rsp]
	xor rax, rax
	inc rax
	xor rdi, rdi
	inc rdi

	xor rdx, rdx
	add dl, 0x9
	syscall

	xor rax, rax
	mov al, 0x3C
	xor rdi, rdi
	syscall

```

By using this command you can compile it.

```bash
$ nasm -felf64 shellcode.asm
$ ld shellcode.o -o shellcode
$ ./shellcode
```


You must extract byte codes from shellcode.o file. There are some tools to doing it. I will share it in references section.


Now this is our C code for executing the shellcode

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>

#define STACK_SIZE 1024 * 1024

unsigned char shellcode[] = "\x4d\x31\xe4\x41\x54\x49\xbc\x64\x61\x6d\x6e\x20\x69\x74\x0a\x41\x54\x48\x8d\x34\x24\x48\31\xc0\x48\xff\xc0\x48\x31\xff\x48\xff\xc7\x48\x48\x31\xd2\x80\xc2\x09\x0f\x05\x48\x31\xc0\xb0\x3c\x48\x31\xff\x0f\x05";

unsigned int len = sizeof(shellcode);


int main()
{
	pid_t ppid = getpid();
	printf("ppid: %ld\n", ppid);

	void *mem = mmap(NULL, len, (PROT_READ | PROT_WRITE | PROT_EXEC), (MAP_PRIVATE | MAP_ANONYMOUS), -1, 0);
	if (mem == MAP_FAILED) return 1;

	memcpy(mem, shellcode, len);

	if (mprotect(mem, len, (PROT_READ | PROT_EXEC)) != 0)
	{
		return 2;
	}

	int (*foo)() = (int (*)())mem;

	/*
		If you want to execute it without using clone syscall
	   
	int (*foo)() = (int(*)())mem;
	foo();

	return 0;	
	 */

	void *stack = malloc(STACK_SIZE * sizeof(void));

	pid_t cpid = clone(foo, stack + STACK_SIZE, (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | SIGCHLD), NULL);
	if (cpid == -1) return 3;

	printf("cpid: %ld\n", cpid);

	waitpid(cpid, NULL, 0);
	free(stack);

	return 0;
}
```


Compile it by using GCC.


```bash
$ gcc shellcode_executor.c -o shellcode_executor
```

Everything ready for executing. As I said before, you may not use clone syscall to execute function pointer, but I decided to execute it with clone syscall.

![image](../assets/images/Linux%20Shellcode%20Injection/shellcode_execution.png)

*ppid: parent process id, cpid: child process id*


Everything is done. Now every step works very well. If there is a mistake that you have noticed, you may send a mail to me. That's all


# References

[mmap](https://man7.org/linux/man-pages/man2/mmap.2.html)

[mprotect](https://man7.org/linux/man-pages/man2/mprotect.2.html)

[clone](https://man7.org/linux/man-pages/man2/clone3.2.html)

[memcpy](https://man7.org/linux/man-pages/man3/memcpy.3.html)
