#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
// IDT，中断描述符表
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < ARRAY_SIZE(excnames))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}

// 声明一系列的处理函数，这些函数在trapentry.S中已经定义了，数字对应的中断类型在trap.h看T_*宏
void t_divide();
void t_debug();
void t_nmi();
void t_brkpt();
void t_oflow();
void t_bound();
void t_illop();
void t_device();
void t_dblflt();
void t_tss();
void t_segnp();
void t_stack();
void t_gpflt();
void t_pgflt();
void t_fperr();
void t_align();
void t_mchk();
void t_simderr();
void t_syscall();

// 设置IDT的表项，设置tss结构，加载tss段选择子到TR，设置tss段在GDT中的表项
void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
	// 设置中断描述符表IDT，SETGATE(gate, istrap, sel, off, dpl)，这里段选择子都是GD_KT内核代码段，偏移就是各个处理函数的偏移，DPL都是0，表示内核才能调用
	SETGATE(idt[T_DIVIDE], 0, GD_KT, t_divide, 0);
	SETGATE(idt[T_DEBUG], 0, GD_KT, t_debug, 0);
	SETGATE(idt[T_NMI], 0, GD_KT, t_nmi, 0);
	// 为什么这里是dpl = 3?，因为后面我们的breakpoint.c测试程序会执行int 3指令，也就是软中断，调用3号中断处理程序（通过这个表项），
	// 如果这个表项的dpl设置成0也就是内核特权级，那么用breakpoint.c执行int 3就会引发一个通用保护异常，也就是T_GPFLT，
	// 把3改成0，然后执行make grade，找到breakpoint的输出文件，里面打印的trapframe显示general protection
	SETGATE(idt[T_BRKPT], 0, GD_KT, t_brkpt, 3); 
	SETGATE(idt[T_OFLOW], 0, GD_KT, t_oflow, 0);
	SETGATE(idt[T_BOUND], 0, GD_KT, t_bound, 0);
	SETGATE(idt[T_ILLOP], 0, GD_KT, t_illop, 0);
	SETGATE(idt[T_DEVICE], 0, GD_KT, t_device, 0);
	SETGATE(idt[T_DBLFLT], 0, GD_KT, t_dblflt, 0);
	SETGATE(idt[T_TSS], 0, GD_KT, t_tss, 0);
	SETGATE(idt[T_SEGNP], 0, GD_KT, t_segnp, 0);
	SETGATE(idt[T_STACK], 0, GD_KT, t_stack, 0);
	SETGATE(idt[T_GPFLT], 0, GD_KT, t_gpflt, 0);
	SETGATE(idt[T_PGFLT], 0, GD_KT, t_pgflt, 0);
	SETGATE(idt[T_FPERR], 0, GD_KT, t_fperr, 0);
	SETGATE(idt[T_ALIGN], 0, GD_KT, t_align, 0);
	SETGATE(idt[T_MCHK], 0, GD_KT, t_mchk, 0);
	SETGATE(idt[T_SIMDERR], 0, GD_KT, t_simderr, 0);
	SETGATE(idt[T_SYSCALL], 0, GD_KT, t_syscall, 3);


	// Per-CPU setup，
	// 设置ts数据结构中记录中断时切换到的内核栈的位置SS0和ESP0，设置GDT中的TSS段表项，加载TSS段选择子到TR寄存器，加载idt地址到IDIR
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct CpuInfo;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//   - Initialize cpu_ts.ts_iomb to prevent unauthorized environments
	//     from doing IO (0 is not the correct value!)
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// LAB 4: Your code here:

	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	ts.ts_esp0 = KSTACKTOP; // 用esp0和ss0定位内核栈的位置，一个段寄存器+sp
	ts.ts_ss0 = GD_KD;
	ts.ts_iomb = sizeof(struct Taskstate);

	// Initialize the TSS slot of the gdt.
	// 在GDT中设置TSS段的表项，指向ts这个变量
	gdt[GD_TSS0 >> 3] = SEG16(STS_T32A, (uint32_t) (&ts),
					sizeof(struct Taskstate) - 1, 0);
	gdt[GD_TSS0 >> 3].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0); // task register，类似其他段寄存器，存放的是GDT的选择子，还有一个隐藏部分，用来缓存GDT中的表项，
	// 通过TR寄存器就可以索引到GDT中的TSS段，然后找到ts这个变量（ts就是内存的一块区域），读取里面存放的更高权限（涉及到权限切换）的新的栈的位置（其实就是内核栈）
	// 然后在这个新的栈里面压入当前进程在用户态的现场：SS、ESP（这俩是因为需要进行权限切换，要使用内核中的栈）、EFLAGS、CS、EIP、ERROR CODE
	// 如果不涉及权限切换的话（这种情况是已经在内核模式，然后收到中断、异常），中断/异常的处理会直接使用当前栈，在栈里面压入EFLAGS、CS、EIP

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	cprintf("trap_dispatch(): ");

	int trapno = tf->tf_trapno; // 在trapentry.S中，我们将一个异常号num压入栈中，也就是trapno，据此去选择具体的处理函数 
	switch (trapno)
	{
	case T_PGFLT: // page fault
		cprintf("page fault\n");
		page_fault_handler(tf);
		break;
	
	case T_BRKPT: // break point，调试器通常插入1字节的int 3指令引发断点异常
		cprintf("break point by int 3\n");
		monitor(tf); // 当执行int 3指令时，调用monitor，相当于当做一个调试器，monitor里可以打印这个trapframe
		break;

	case T_SYSCALL: ;// syscall，参数看lib/syscall()怎么组织的：DX, CX, BX, DI, SI，这里不加一个;会编译报错
		cprintf("system call\n");
		int32_t ret = syscall(tf->tf_regs.reg_eax, tf->tf_regs.reg_edx, tf->tf_regs.reg_ecx, 
								tf->tf_regs.reg_ebx, tf->tf_regs.reg_edi, tf->tf_regs.reg_esi);
		tf->tf_regs.reg_eax = ret; // 返回值放回eax传递给用户空间
		break;

	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	case (IRQ_OFFSET + IRQ_SPURIOUS):
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		break;

	default:  // Unexpected trap: The user process or the kernel has a bug.
		cprintf("unexpected trap\n");
		print_trapframe(tf);
		if (tf->tf_cs == GD_KT)
			panic("unhandled trap in kernel");
		else {
			env_destroy(curenv);
			return;
		}
		break;
	}
}

void
trap(struct Trapframe *tf)
{
	// 这个tf指针是指向内核栈中我们压入的trapframe的指针，所以中断时保存trapframe的逻辑是：首先处理器在tss进程状态栈指出的内核栈里面压入那五个
	// 寄存器，ESP、SS、EFLAGS、CS、EIP，以及可选的一个错误码，然后我们在trapentry.S中继续压入通用寄存器、es、ds、中断号这些值，在栈里面构建一个
	// 完整的trapframe。然后将此时的ESP作为参数传入trap函数，也就是这个tf指针；接着，我们通过CS寄存器的低2位CPL位特权级判断是否是从用户空间陷入内核
	// 是的话那么需要保存现场：也就是将参数tf所指向的trapframe结构保存到当前进程的env_tf结构中。不是的话说明从内核中断的，用户现场肯定已经保存了。
	// 此后，我们就不需要管这个内核栈里的trapframe了，因为已经保存在env结构里了，需要恢复的时候从当前进程的env->env_tf中恢复就行（run_env函数）
	// 会调用env_pop_tf，从env的env_tf结构中弹出进程的现场；



	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Re-acqurie the big kernel lock if we were halted in
	// sched_yield()
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();
	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	// 检测一下是否关中断了，通过中断门或者陷阱门执行的中断处理函数会自动关中断
	assert(!(read_eflags() & FL_IF));

	cprintf("Incoming TRAP frame at %p\n", tf);

	if ((tf->tf_cs & 3) == 3) { // 判断是否从用户模式陷入内核
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
		assert(curenv);

		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		// 如果是从用户模式陷入内核的，从内核栈里面拷贝中断帧，存到进程描述符的tf字段中，以便中断处理完后恢复中断点运行
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		// 栈里面的trapframe结构不用了，之后只使用currenv指向的env结构的env_tf
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	// 根据中断号也就是中断类型调用不同的处理函数，相当于任务的分发
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}

// 页面故障处理函数，如果在内核模式发生页面故障，则系统应该panic；如果是用户模式故障，则分配缺少的内存
// 如何判断是什么模式：cs寄存器的低2位叫cpl = current privilege level，当前特权级，3表示用户模式，0表示内核模式
// 看https://pdos.csail.mit.edu/6.828/2018/readings/i386/s06_03.htm
void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	// 发生页故障时，故障地址被处理器保存在CR2寄存器
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	if ((tf->tf_cs & 3) == 0) // 内核模式下出现了页面故障
		panic("内核模式下页面故障！\n");

	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.
	// 用户模式下的页面故障，不分配物理内存直接销毁进程？
	// 如果后续的lab没有完善这个功能的话，可以尝试自己写一下最基本的处理功能：
	// 参考https://blog.csdn.net/m0_37962600/article/details/81448553

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// It is convenient for our code which returns from a page fault
	// (lib/pfentry.S) to have one word of scratch space at the top of the
	// trap-time stack; it allows us to more easily restore the eip/esp. In
	// the non-recursive case, we don't have to worry about this because
	// the top of the regular user stack is free.  In the recursive case,
	// this means we have to leave an extra word between the current top of
	// the exception stack and the new stack frame because the exception
	// stack _is_ the trap-time stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	// LAB 4: Your code here.

	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

