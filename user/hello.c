// hello, world
#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	cprintf("hello, world!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	 // thisenv所在的内存区域不能被用户访问？不是，是因为thisenv没有初始化指向当前的进程，所以page fault
	cprintf("i am environment %08x\n", thisenv->env_id);
}
