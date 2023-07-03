#ifndef JOS_INC_ELF_H
#define JOS_INC_ELF_H

#define ELF_MAGIC 0x464C457FU	/* "\x7FELF" in little endian */

// elf结构看BOOK/elf.pdf，就三个概念要注意：ELF文件头、section header table、program header table
struct Elf { // ELF文件头
	uint32_t e_magic;	// must equal ELF_MAGIC
	uint8_t e_elf[12];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint32_t e_entry; // 程序入口虚拟地址
	uint32_t e_phoff; // 程序头表偏移
	uint32_t e_shoff; // 段表偏移
	uint32_t e_flags;
	uint16_t e_ehsize;// elf header size，elf文件头大小
	uint16_t e_phentsize; // 程序头表项大小
	uint16_t e_phnum; // 程序头表项数量
	uint16_t e_shentsize; // section header table entry size
	uint16_t e_shnum; // section header 数量
	uint16_t e_shstrndx;
};

struct Proghdr { // 程序头表（一个Proghdr结构的数组）的表项，保存了一个segment的信息，segment是section的链接视图，包含几个类似的section
	uint32_t p_type;
	uint32_t p_offset; // segment在文件中的偏移
	uint32_t p_va;
	uint32_t p_pa; // segment的物理地址
	uint32_t p_filesz;
	uint32_t p_memsz; // segment在内存中的映像的大小
	uint32_t p_flags;
	uint32_t p_align;
};

struct Secthdr { // 段表的表项，表示一个section的信息
	uint32_t sh_name;	// 名字
	uint32_t sh_type;
	uint32_t sh_flags;
	uint32_t sh_addr;  	// 这个section的虚拟地址
	uint32_t sh_offset; // 这个section在文件中的偏移
	uint32_t sh_size;	// section size
	uint32_t sh_link;
	uint32_t sh_info;
	uint32_t sh_addralign;
	uint32_t sh_entsize;
};

// Values for Proghdr::p_type
#define ELF_PROG_LOAD		1

// Flag bits for Proghdr::p_flags
#define ELF_PROG_FLAG_EXEC	1
#define ELF_PROG_FLAG_WRITE	2
#define ELF_PROG_FLAG_READ	4

// Values for Secthdr::sh_type
#define ELF_SHT_NULL		0
#define ELF_SHT_PROGBITS	1
#define ELF_SHT_SYMTAB		2
#define ELF_SHT_STRTAB		3

// Values for Secthdr::sh_name
#define ELF_SHN_UNDEF		0

#endif /* !JOS_INC_ELF_H */
