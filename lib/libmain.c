// Called from entry.S to get us going.
// entry.S already took care of defining envs, pages, uvpd, and uvpt.

#include <inc/lib.h>

extern void umain(int argc, char **argv);

const volatile struct Env *thisenv;
const char *binaryname = "<unknown>";

void
libmain(int argc, char **argv)
{
	// set thisenv to point at our Env structure in envs[].
	// LAB 3: Your code here.
	cprintf("lib/libmain()\n"); // 这里要注意，调用cprintf最终会调用cputs系统调用，以及后面的getenvid都是系统调用，都会中断运行
	thisenv = envs + ENVX(sys_getenvid()); // 这里不能直接用sys_getenvid()去索引envs，因为envid的低10位才是索引
	
	// save the name of the program so that panic() can use it
	if (argc > 0)
		binaryname = argv[0];

	// call user main routine
	umain(argc, argv);

	// exit gracefully
	exit();
}

