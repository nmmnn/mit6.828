// program to cause a breakpoint trap

#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	asm volatile("int $3"); // 执行int 3，调用3号中断，也就是break point
}

