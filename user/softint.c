// buggy program - causes an illegal software interrupt

#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	asm volatile("int $14");	// page fault，试图在用户态执行int指令，int指令要求的特权级为0，是系统指令，特权级为3的程序不能执行这个指令，所以引发保护异常trap 13
}

