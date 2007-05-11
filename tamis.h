#ifndef __TAMIS_H__
#define __TAMIS_H__

struct tamis_tls {
	uint8_t old_opcode;
	void *to_protect_mem;
	size_t to_protect_len;
};

struct tamis_memzone {
	void *mem;
	void *page;
	int len;
};
#define BREAK_INSN 0xcc

#define PAGE_SIZE 4096
#define SIZE (sizeof(int)*126)

#endif /* __TAMIS_H__ */
