/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/mmu.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>
#include <inc/elf.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/monitor.h>
#include <kern/sched.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>

struct Env *envs = NULL;		// All environments
static struct Env *env_free_list;	// Free environment list
					// (linked by Env->env_link)

#define ENVGENSHIFT	12		// >= LOGNENV

// Global descriptor table.
//
// Set up global descriptor table (GDT) with separate segments for
// kernel mode and user mode.  Segments serve many purposes on the x86.
// We don't use any of their memory-mapping capabilities, but we need
// them to switch privilege levels. 
//
// The kernel and user segments are identical except for the DPL.
// To load the SS register, the CPL must equal the DPL.  Thus,
// we must duplicate the segments for the user and the kernel.
//
// In particular, the last argument to the SEG macro used in the
// definition of gdt specifies the Descriptor Privilege Level (DPL)
// of that descriptor: 0 for kernel and 3 for user.
// 全局描述符表，16位段选择子：偏移->线性虚拟地址->物理地址，JOS中不使用段进行内存映射的功能，所有段的基址都是0x0，长度都是4G
// 相当于没有分段功能，仅仅用来切换优先级
// SEG(type, base, limit, dpl)，可以看到，下面所有段的基址和长度都是一样的，所以得到的都是同一个段（相当于偏移就是对应的线性虚拟地址），而我们只用
// 类型以及DPL权限
struct Segdesc gdt[NCPU + 5] =
{
	// 0x0 - unused (always faults -- for trapping NULL far pointers)
	SEG_NULL,

	// 0x8 - kernel code segment
	[GD_KT >> 3] = SEG(STA_X | STA_R, 0x0, 0xffffffff, 0),

	// 0x10 - kernel data segment
	[GD_KD >> 3] = SEG(STA_W, 0x0, 0xffffffff, 0),

	// 0x18 - user code segment
	[GD_UT >> 3] = SEG(STA_X | STA_R, 0x0, 0xffffffff, 3),

	// 0x20 - user data segment
	[GD_UD >> 3] = SEG(STA_W, 0x0, 0xffffffff, 3),

	// Per-CPU TSS descriptors (starting from GD_TSS0) are initialized
	// in trap_init_percpu()
	[GD_TSS0 >> 3] = SEG_NULL
};

struct Pseudodesc gdt_pd = {
	sizeof(gdt) - 1, (unsigned long) gdt
};

//
// Converts an envid to an env pointer.
// If checkperm is set, the specified environment must be either the
// current environment or an immediate child of the current environment.
//
// RETURNS
//   0 on success, -E_BAD_ENV on error.
//   On success, sets *env_store to the environment.
//   On error, sets *env_store to NULL.
//
int
envid2env(envid_t envid, struct Env **env_store, bool checkperm)
{
	struct Env *e;

	// If envid is zero, return the current environment.
	if (envid == 0) {
		*env_store = curenv;
		return 0;
	}

	// Look up the Env structure via the index part of the envid,
	// then check the env_id field in that struct Env
	// to ensure that the envid is not stale
	// (i.e., does not refer to a _previous_ environment
	// that used the same slot in the envs[] array).
	e = &envs[ENVX(envid)];
	if (e->env_status == ENV_FREE || e->env_id != envid) {
		*env_store = 0;
		return -E_BAD_ENV;
	}

	// Check that the calling environment has legitimate permission
	// to manipulate the specified environment.
	// If checkperm is set, the specified environment
	// must be either the current environment
	// or an immediate child of the current environment.
	if (checkperm && e != curenv && e->env_parent_id != curenv->env_id) {
		*env_store = 0;
		return -E_BAD_ENV;
	}

	*env_store = e;
	return 0;
}

// Mark all environments in 'envs' as free, set their env_ids to 0,
// and insert them into the env_free_list.
// Make sure the environments are in the free list in the same order
// they are in the envs array (i.e., so that the first call to
// env_alloc() returns envs[0]).
//
void
env_init(void)
{
	// Set up envs array
	// LAB 3: Your code here.
	env_free_list = NULL;
	for (int i = NENV - 1; i >= 0; --i) { // 倒过来优雅一点，这里用size_t会出错，debug trap，应该是size_t被减到-1了
		envs[i].env_id = 0;
		envs[i].env_link = env_free_list;
		env_free_list = &envs[i];
	}

	// Per-CPU part of the initialization
	env_init_percpu(); // 加载全局描述符表并设置段寄存器，为什么这里又要做一遍？
}

// Load GDT and segment descriptors.
// 加载全局描述符表和段选择器（保护模式下段寄存器是段基址，这里段寄存器变成了GDT的选择子）
void
env_init_percpu(void)
{
	lgdt(&gdt_pd); // 这条指令加载全局描述符表到GDTR中
	// 加载GDT后，x86将描述符的信息存储在段寄存器中，避免每次都查阅描述符表，段寄存器是16位的，这是可见部分，每个段寄存器还对应一个(32位？)的不可见部分
	// 这个不可见部分就是从GDTR中获取的段基址以及限制、类型信息
	// 加载这些段寄存器的的指令分为两类：一种是直接加载，用mov等指令，可以直接加载GS FS ES DS SS等段寄存器
	// 另一种是间接加载指令，用far call 或者 far jmp指令可以隐式的加载CS段寄存器，这也就是之前在boot.s中做的事情
	// 详见：https://pdos.csail.mit.edu/6.828/2018/readings/i386/s05_01.htm

	// The kernel never uses GS or FS, so we leave those set to
	// the user data segment.
	asm volatile("movw %%ax,%%gs" : : "a" (GD_UD|3));
	asm volatile("movw %%ax,%%fs" : : "a" (GD_UD|3));
	// The kernel does use ES, DS, and SS.  We'll change between
	// the kernel and user data segments as needed.
	asm volatile("movw %%ax,%%es" : : "a" (GD_KD));
	asm volatile("movw %%ax,%%ds" : : "a" (GD_KD));
	asm volatile("movw %%ax,%%ss" : : "a" (GD_KD));
	// Load the kernel text segment into CS.
	asm volatile("ljmp %0,$1f\n 1:\n" : : "i" (GD_KT));
	// For good measure, clear the local descriptor table (LDT),
	// since we don't use it.
	lldt(0);
}

//
// Initialize the kernel virtual memory layout for environment e.
// Allocate a page directory, set e->env_pgdir accordingly,
// and initialize the kernel portion of the new environment's address space.
// Do NOT (yet) map anything into the user portion
// of the environment's virtual address space.
//
// Returns 0 on success, < 0 on error.  Errors include:
//	-E_NO_MEM if page directory or table could not be allocated.
// 初始化进程e的内核虚拟内存布局，分配一个物理页作为页目录表并设置env_pgdir，初始化进程虚拟地址空间的内核部分（内核部分处理UVPT保存进程的页目录外都一样）
static int
env_setup_vm(struct Env *e)
{
	int i;
	struct PageInfo *p = NULL;

	// Allocate a page for the page directory
	if (!(p = page_alloc(ALLOC_ZERO)))
		return -E_NO_MEM;

	// Now, set e->env_pgdir and initialize the page directory.
	//
	// Hint:
	//    - The VA space of all envs is identical above UTOP
	//	(except at UVPT, which we've set below).
	//	See inc/memlayout.h for permissions and layout.
	//	Can you use kern_pgdir as a template?  Hint: Yes.
	//	(Make sure you got the permissions right in Lab 2.)
	//    - The initial VA below UTOP is empty.
	//    - You do not need to make any more calls to page_alloc.
	//    - Note: In general, pp_ref is not maintained for
	//	physical pages mapped only above UTOP, but env_pgdir
	//	is an exception -- you need to increment env_pgdir's
	//	pp_ref for env_free to work correctly.
	//    - The functions in kern/pmap.h are handy.

	// LAB 3: Your code here.
	// 去看memlayout.h，对于所有进程来说，UTOP上面的虚拟地址空间都是相同的，除了UVPT，因为UVPT开始的4M（PTSIZE）虚拟内存存放的是当前进程的页目录
	// UVPT下面4M也就是UPAGES开始的虚拟地址映射的是内核的页目录，再下面4M也就是UENV开始的虚拟地址映射的是envs数组，这些都是相同的，所以这里我们设置
	// 进程e的虚拟地址空间的UVPT位置为它自己的页目录表，以及UTOP以上的所有其他部分（所有进程都是一样的）
	p->pp_ref++;
	e->env_pgdir = (pde_t*) page2kva(p); // 环境e的页目录地址，这里是把物理地址转为kernel地址（方便得到物理地址）
	memcpy(e->env_pgdir, kern_pgdir, PGSIZE); // 直接拷贝一份内核页目录，不同的地方只在UVPT处的映射，应该是自己的页目录表

	// UVPT maps the env's own page table read-only.
	// Permissions: kernel R, user R
	// 内核页目录的UVPT表项存的是内核页目录表的物理地址，UVPT映射的是当前进程的页目录，所以这里需要修改表项，改成e的页目录物理地址
	e->env_pgdir[PDX(UVPT)] = PADDR(e->env_pgdir) | PTE_P | PTE_U;

	return 0;
}

//
// Allocates and initializes a new environment.
// On success, the new environment is stored in *newenv_store.
//
// Returns 0 on success, < 0 on failure.  Errors include:
//	-E_NO_FREE_ENV if all NENV environments are allocated
//	-E_NO_MEM on memory exhaustion
// 从env_free_list摘一个env，然后分配一个页目录并设置env的内核内存布局，生成一个env_id，设置父进程id，设置寄存器状态
int
env_alloc(struct Env **newenv_store, envid_t parent_id)
{
	cprintf("env_alloc()\n");
	int32_t generation;
	int r;
	struct Env *e;

	if (!(e = env_free_list))
		return -E_NO_FREE_ENV;

	// Allocate and set up the page directory for this environment.
	if ((r = env_setup_vm(e)) < 0)
		return r;

	// Generate an env_id for this environment.
	generation = (e->env_id + (1 << ENVGENSHIFT)) & ~(NENV - 1);
	if (generation <= 0)	// Don't create a negative env_id.
		generation = 1 << ENVGENSHIFT;
	e->env_id = generation | (e - envs);

	// Set the basic status variables.
	e->env_parent_id = parent_id;
	e->env_type = ENV_TYPE_USER;
	e->env_status = ENV_RUNNABLE;
	e->env_runs = 0;

	// Clear out all the saved register state,
	// to prevent the register values
	// of a prior environment inhabiting this Env structure
	// from "leaking" into our new environment.
	memset(&e->env_tf, 0, sizeof(e->env_tf));

	// Set up appropriate initial values for the segment registers.
	// GD_UD is the user data segment selector in the GDT, and
	// GD_UT is the user text segment selector (see inc/memlayout.h).
	// The low 2 bits of each segment register contains the
	// Requestor Privilege Level (RPL); 3 means user mode.  When
	// we switch privilege levels, the hardware does various
	// checks involving the RPL and the Descriptor Privilege Level
	// (DPL) stored in the descriptors themselves.
	e->env_tf.tf_ds = GD_UD | 3;
	e->env_tf.tf_es = GD_UD | 3;
	e->env_tf.tf_ss = GD_UD | 3;
	e->env_tf.tf_esp = USTACKTOP;
	e->env_tf.tf_cs = GD_UT | 3;
	// You will set e->env_tf.tf_eip later.

	// Enable interrupts while in user mode.
	// LAB 4: Your code here.

	// Clear the page fault handler until user installs one.
	e->env_pgfault_upcall = 0;

	// Also clear the IPC receiving flag.
	e->env_ipc_recving = 0;

	// commit the allocation
	env_free_list = e->env_link;
	*newenv_store = e;

	cprintf("[%08x] new env %08x\n", curenv ? curenv->env_id : 0, e->env_id);
	return 0;
}

//
// Allocate len bytes of physical memory for environment env,
// and map it at virtual address va in the environment's address space.
// Does not zero or otherwise initialize the mapped pages in any way.
// Pages should be writable by user and kernel.
// Panic if any allocation attempt fails.
// 分配len字节的物理内存给env，然后映射到他的虚拟地址va处，通过修改env->pgdir表项以及页表表项实现
static void
region_alloc(struct Env *e, void *va, size_t len)
{
	// LAB 3: Your code here.
	// (But only if you need it for load_icode.)
	//
	// Hint: It is easier to use region_alloc if the caller can pass
	//   'va' and 'len' values that are not page-aligned.
	//   You should round va down, and round (va + len) up.
	//   (Watch out for corner-cases!)
	va = ROUNDDOWN(va, PGSIZE); // va地址需要向下调整到一个页的边界处
	size_t npgs = ROUNDUP(len, PGSIZE) / PGSIZE; // len向上调整到页边界大小，得到页面数量

	for (size_t i = 0; i < npgs; ++i) {
		struct PageInfo* pp = page_alloc(0); // 分配一个物理页面
		if (pp == NULL)
			panic("region_alloc(): page_alloc()失败，空闲物理页不足！");

		page_insert(e->env_pgdir, pp, va, PTE_W | PTE_U); // 物理页面映射到va（修改页目录表、页表、页面引用计数）
		va += PGSIZE; // 移动va到下一个位置
	}

}

//
// Set up the initial program binary, stack, and processor flags
// for a user process.
// This function is ONLY called during kernel initialization,
// before running the first user-mode environment.
//
// This function loads all loadable **segments** from the ELF binary image
// into the environment's user memory, starting at the appropriate
// virtual addresses **indicated in the ELF program header**.
// At the same time it clears to zero any portions of these segments
// that are marked in the program header as being mapped
// but not actually present in the ELF file - i.e., the program's bss section.
//
// All this is very similar to what our boot loader does, except the boot
// loader also needs to read the code from disk.  Take a look at
// boot/main.c to get ideas.
//
// Finally, this function maps one page for the program's initial stack.
//
// load_icode panics if it encounters problems.
//  - How might load_icode fail?  What might be wrong with the given input?
// 给进程e加载二进制文件，将各个segment装进物理内存，并设置虚拟内存到物理内存的映射
static void
load_icode(struct Env *e, uint8_t *binary)
{
	// Hints:
	//  Load each program segment into **virtual memory**
	//  at the address specified in the ELF segment header.
	//  You should only load segments with ph->p_type == ELF_PROG_LOAD.
	//  Each segment's virtual address can be found in ph->p_va
	//  and its size in memory can be found in ph->p_memsz.
	//  The ph->p_filesz bytes from the ELF binary, starting at
	//  'binary + ph->p_offset', should be copied to virtual address
	//  ph->p_va.  Any remaining memory bytes should be cleared to zero.
	//  (The ELF header should have ph->p_filesz <= ph->p_memsz.)
	//  Use functions from the previous lab to allocate and map pages.
	//
	//  All page protection bits should be user read/write for now.
	//  ELF segments are not necessarily page-aligned, but you can
	//  assume for this function that no two segments will touch
	//  the same virtual page.
	//
	//  You may find a function like region_alloc useful.
	//
	//  Loading the segments is much simpler if you can move data
	//  directly into the virtual addresses stored in the ELF binary.
	//  So which page directory should be in force during
	//  this function?
	//
	//  You must also do something with the program's entry point,
	//  to make sure that the environment starts executing there.
	//  What?  (See env_run() and env_pop_tf() below.)

	// LAB 3: Your code here.
	cprintf("load_icode()\n");
	struct Elf* ELFHDR = (struct Elf*) binary;

	// 检查格式
	if (ELFHDR->e_magic != ELF_MAGIC)
		panic("错误的ELF格式");

	// 按照main.c的方式遍历program header项，加载的方式换成memcpy，在此之前需要先给进程分配物理空间并映射到虚拟地址，也就是说并没有lazy alloc
	struct Proghdr* ph, *eph;
	ph = (struct Proghdr*) ((uint8_t*)ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;

	// 切换页目录，因为下面memset、memcpy函数使用的虚拟地址空间是专属于进程的，而非内核或其他进程的，这里相当于切换虚拟地址空间
	lcr3(PADDR(e->env_pgdir));

	for (; ph < eph; ++ph) {
		if (ph->p_type == ELF_PROG_LOAD) { // 只有load类型的segment需要加载，包括BSS段
			region_alloc(e, (void*) ph->p_va, ph->p_memsz); // 分配memsz大小的物理内存，映射到进程虚拟地址空间p_va处
			// 注意：p_memsz是这个segment在虚拟内存中的大小，filesz是这个segment在文件中的大小，正常来说这俩应该一样，
			// 但是像BSS这种段，需要进行清零，为了节约空间，filesz为0，但是memsz不为零，这里统一处理，先清零，再拷贝
			memset((void*) ph->p_va, 0, ph->p_memsz); 
			memcpy((void*) ph->p_va, (void*) ELFHDR + ph->p_offset, ph->p_filesz); // 如果是BSS段，那么filesz=0
		}
	}

	// Now map one page for the program's initial stack
	// at virtual address USTACKTOP - PGSIZE.

	// struct PageInfo* pp = page_alloc(ALLOC_ZERO);
	// if (pp == NULL)
	// 	panic("load_icode: 没有可用物理页!");

	// int ret = page_insert(e->env_pgdir, pp, (void*)(USTACKTOP - PGSIZE), PTE_U | PTE_W);
	// if (ret == -E_NO_MEM)
	// 	panic("load_icode: 页表分配失败!");
	// 上面这一堆用region_alloc就行，分配一个页面初始化进程的栈
	region_alloc(e, (void*) (USTACKTOP - PGSIZE), PGSIZE);

	// 切换回去
	lcr3(PADDR(kern_pgdir));

	e->env_tf.tf_eip = ELFHDR->e_entry; // 设置入口地址，直接保存在进程的trapframe里

	// LAB 3: Your code here.
}

//
// Allocates a new env with env_alloc, loads the named elf
// binary into it with load_icode, and sets its env_type.
// This function is ONLY called during kernel initialization,
// before running the first user-mode environment.
// The new env's parent ID is set to 0. 
// 创建一个进程、加载binary这个二进制文件到物理内存，并设置到进程虚拟地址空间的映射
void
env_create(uint8_t *binary, enum EnvType type)
{
	// LAB 3: Your code here.
	cprintf("env_create()\n");
	struct Env* pNewEnv;
	if (env_alloc(&pNewEnv, 0) < 0)
		panic("env_alloc() 失败！");

	load_icode(pNewEnv, binary);
	pNewEnv->env_type = type;
}

//
// Frees env e and all memory it uses.
//
void
env_free(struct Env *e)
{
	pte_t *pt;
	uint32_t pdeno, pteno;
	physaddr_t pa;

	// If freeing the current environment, switch to kern_pgdir
	// before freeing the page directory, just in case the page
	// gets reused.
	if (e == curenv)
		lcr3(PADDR(kern_pgdir));

	// Note the environment's demise.
	cprintf("[%08x] free env %08x\n", curenv ? curenv->env_id : 0, e->env_id);

	// Flush all mapped pages in the user portion of the address space
	static_assert(UTOP % PTSIZE == 0);
	for (pdeno = 0; pdeno < PDX(UTOP); pdeno++) {

		// only look at mapped page tables
		if (!(e->env_pgdir[pdeno] & PTE_P))
			continue;

		// find the pa and va of the page table
		pa = PTE_ADDR(e->env_pgdir[pdeno]);
		pt = (pte_t*) KADDR(pa);

		// unmap all PTEs in this page table
		for (pteno = 0; pteno <= PTX(~0); pteno++) {
			if (pt[pteno] & PTE_P)
				page_remove(e->env_pgdir, PGADDR(pdeno, pteno, 0));
		}

		// free the page table itself
		e->env_pgdir[pdeno] = 0;
		page_decref(pa2page(pa));
	}

	// free the page directory
	pa = PADDR(e->env_pgdir);
	e->env_pgdir = 0;
	page_decref(pa2page(pa));

	// return the environment to the free list
	e->env_status = ENV_FREE;
	e->env_link = env_free_list;
	env_free_list = e;
}

//
// Frees environment e.
// If e was the current env, then runs a new environment (and does not return
// to the caller).
//
void
env_destroy(struct Env *e)
{
	// If e is currently running on other CPUs, we change its state to
	// ENV_DYING. A zombie environment will be freed the next time
	// it traps to the kernel.
	if (e->env_status == ENV_RUNNING && curenv != e) {
		e->env_status = ENV_DYING;
		return;
	}

	env_free(e);

	if (curenv == e) {
		curenv = NULL;
		sched_yield();
	}
}


//
// Restores the register values in the Trapframe with the 'iret' instruction.
// This exits the kernel and starts executing some environment's code.
//
// This function does not return.
// popal会弹出8个通用寄存器值，es和ds需要我们自己弹（在后面中断那里也需要自己压入trapframe中），trapno跳过
// iret中断返回指令将SS、ESP、CS、EIP、EFLAGS弹出
void
env_pop_tf(struct Trapframe *tf)
{
	cprintf("env_pop_rf()\n");
	
	// Record the CPU we are running on for user-space debugging
	curenv->env_cpunum = cpunum();

	
	asm volatile(
		"\tmovl %0,%%esp\n"
		"\tpopal\n"
		"\tpopl %%es\n"
		"\tpopl %%ds\n"
		"\taddl $0x8,%%esp\n" /* skip tf_trapno and tf_errcode */
		"\tiret\n"
		: : "g" (tf) : "memory");
	panic("iret failed");  /* mostly to placate the compiler */
}

//
// Context switch from curenv to env e.
// Note: if this is the first call to env_run, curenv is NULL.
//
// This function does not return.
// 这里只是运行下一个进程e，并没有对上一个进程的状态进行保存
void
env_run(struct Env *e)
{
	// Step 1: If this is a context switch (a new environment is running):
	//	   1. Set the current environment (if any) back to
	//	      ENV_RUNNABLE if it is ENV_RUNNING (think about
	//	      what other states it can be in),
	//	   2. Set 'curenv' to the new environment,
	//	   3. Set its status to ENV_RUNNING,
	//	   4. Update its 'env_runs' counter,
	//	   5. Use lcr3() to switch to its address space.
	// Step 2: Use env_pop_tf() to restore the environment's
	//	   registers and drop into user mode in the
	//	   environment.

	// Hint: This function loads the new environment's state from
	//	e->env_tf.  Go back through the code you wrote above
	//	and make sure you have set the relevant parts of
	//	e->env_tf to sensible values.

	// LAB 3: Your code here.
	cprintf("env_run()\n");
	if (curenv != NULL && curenv->env_status == ENV_RUNNING) { 
		curenv->env_status = ENV_RUNNABLE;
	}
	curenv = e;
	curenv->env_status = ENV_RUNNING;
	curenv->env_runs++;
	lcr3(PADDR(curenv->env_pgdir)); // 加载页目录地址
	// cprintf("env_run(): next env_pop_tf()\n");
	env_pop_tf(&curenv->env_tf);	// 加载新进程的寄存器状态
	// panic("env_run not yet implemented");
}

