/*
    opcode.c - x86 emulation code
    Copyright (C) 2008  Frederik Deweerdt <frederik.deweerdt@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/


#include <assert.h>
#include <dis-asm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <stdarg.h>


#if defined(__i386__)
#define REG_RAX REG_EAX
#define REG_RBX REG_EBX
#define REG_RCX REG_ECX
#define REG_RDX REG_EDX
#define REG_RSI REG_ESI
#define REG_RSP REG_ESP
#define REG_RIP REG_EIP
#endif

struct opcode_str {
	char opcode[32];
	char src[32];
	unsigned long long soffset;
	int has_soffset;
	char dest[32];
	unsigned long long doffset;
	int has_doffset;
	int asm_len; 	/* the length of the decoded opcode */
};

static struct opcode_str *parse_disassembly(char *str)
{
	struct opcode_str *op;
	char *p = str, *d;
	int first_comma = 1;
	int spaces = 0;
	char buf[32];

	op = calloc(1, sizeof(*op));
	if (!op)
		return NULL;

	d = op->opcode;
	do {
		/* we parsed the opcode, parse the src now */
		if (*p == ' ' && !spaces) {
			*d = '\0';
			d = op->src;
			/* skip extraneaous whitespaces */
			while (*p == ' ')
				p++;
			spaces++;
		}
		

		/* we parsed the src, parse the dest now */
		if (*p == ',' && first_comma) {
			*d = '\0';
			d = op->dest;
			p++;
			first_comma = 0;
		}
		*d++ = *p++;
	} while(*p && !(*p == ' ' && spaces > 1));

	memcpy(buf, op->src, sizeof(buf));
	if (sscanf(buf, "%lli(%s)", &op->soffset, op->src) == 2) {
		op->has_soffset = 1;
	}

	memcpy(buf, op->dest, sizeof(buf));
	if (sscanf(buf, "%lli(%s)", &op->doffset, op->dest) == 2) {
		op->has_doffset = 1;
	}

	return op;
}

/* Pseudo FILE object for strings. */
struct SFILE {
	char *buffer;
	size_t pos;
	size_t alloc;
};

static struct SFILE *alloc_sfile()
{
	struct SFILE *f;
	f = malloc(sizeof(*f));
	if (!f)
		return NULL;
	f->buffer = malloc(BUFSIZ);
	if (!f->buffer) {
		free(f);
		return NULL;
	}

	f->alloc = BUFSIZ;
	f->pos = 0;

	return f;
}

void free_sfile(struct SFILE *f)
{
	free(f->buffer);
	free(f);
}

/* sprintf to a "stream".  */
static int tamis_sprintf (struct SFILE *f, const char *format, ...)
{
	size_t n;
	va_list args;

	while (1) {
		size_t space = f->alloc - f->pos;

		va_start (args, format);
		n = vsnprintf (f->buffer + f->pos, space, format, args);
		va_end (args);

		if (space > n)
			break;

		f->alloc = (f->alloc + n) * 2;
		f->buffer = realloc(f->buffer, f->alloc);
	}

	f->pos += n;

	return n;
}



static struct opcode_str *disassemble_insn_at(uint8_t *address)
{
	struct disassemble_info disasm_info;
	struct opcode_str *op;
	struct SFILE *str = alloc_sfile();
	int asm_len;

	init_disassemble_info(&disasm_info, str, (fprintf_ftype)tamis_sprintf);
	disasm_info.mach = bfd_mach_i386_i386;
	disasm_info.buffer = address;
	disasm_info.buffer_vma = (bfd_vma)address;
	disasm_info.buffer_length = 64; /* XXX: should be the max len of an insn */
#if defined(__i386__)
	disasm_info.disassembler_options = "i386";
#else
	disasm_info.disassembler_options = "x86-64";
#endif

	asm_len = print_insn_i386((bfd_vma)address, &disasm_info);

	op = parse_disassembly(str->buffer);
	if (!op)
		goto out;

	op->asm_len = asm_len;

	free_sfile(str);

out:
	return op;
}

enum location_type {
	REGISTER,
	REGISTER_DEREF,
	IMMEDIATE,
	ADDRESS,
};

struct location {
	enum location_type type;
	union {
		unsigned long immediate;
		unsigned long reg_no;
		unsigned long address;
	};
	unsigned long offset;
	unsigned long size;
};
static struct location *str_to_location(const char *str)
{
	struct location *l;

	l = malloc(sizeof(*l));
	if (!l)
		return NULL;

	l->size = 64;

	while ((*str == '%' || *str == '('
	        || *str == 'e' || *str == 'r') && *str != '\0' ) {
		if (*str == 'e') {
			l->size = 32;
		}
		str++;
	}

	if (*str == '\0')
		return NULL;

	/* immediate value */
	if (*str == '$') {
		l->type = IMMEDIATE;
		l->immediate = strtol(str + 1, NULL, 0);
		goto out;
	}

	/* address value */
	if (*str == '0' && *(str + 1) == 'x' && !index(str, '(')) {
		l->type = ADDRESS;
		l->address = strtol(str, NULL, 0);
		goto out;
	}

	/* register */
	if (index(str, ')'))
		l->type = REGISTER_DEREF;
	else
		l->type = REGISTER;

	switch (*str) {
	case 'a':
		l->reg_no = REG_RAX;
		goto out;
	case 'b':
		l->reg_no = REG_RBX;
		goto out;
	case 'c':
		l->reg_no = REG_RCX;
		goto out;
	case 'd':
		l->reg_no = REG_RDX;
		goto out;
	case 'i':
		l->reg_no = REG_RIP;
		goto out;
	case 's':
		switch(*(str+1)) {
		case 'i':
			l->reg_no = REG_RSI;
			goto out;
		case 'p':
			l->reg_no = REG_RSP;
			goto out;
		}
	}

	abort();
out:
	return l;
}

unsigned long get_val_addr(struct location *l, mcontext_t *context)
{
	unsigned long ret = 0;
	switch (l->type) {
	case REGISTER_DEREF:
		ret = context->gregs[l->reg_no];
		break;
	case REGISTER:
		ret = (unsigned long)&context->gregs[l->reg_no];
		break;
	case IMMEDIATE:
		ret = (unsigned long)&l->immediate;
		break;
	case ADDRESS:
		ret = l->address;
		break;
	default:
		abort();
	}
	return ret;
}

#if defined(x86_64)
static char *regname(int regno)
{
	static char regs[][32] = {
		[REG_R8] = "REG_R8",
		[REG_R9] = "REG_R9",
		[REG_R10] = "REG_R10",
		[REG_R11] = "REG_R11",
		[REG_R12] = "REG_R12",
		[REG_R13] = "REG_R13",
		[REG_R14] = "REG_R14",
		[REG_R15] = "REG_R15",
		[REG_RDI] = "REG_RDI",
		[REG_RSI] = "REG_RSI",
		[REG_RBP] = "REG_RBP",
		[REG_RBX] = "REG_RBX",
		[REG_RDX] = "REG_RDX",
		[REG_RAX] = "REG_RAX",
		[REG_RCX] = "REG_RCX",
		[REG_RSP] = "REG_RSP",
		[REG_RIP] = "REG_RIP",
		[REG_EFL] = "REG_EFL",
		[REG_CSGSFS] = "REG_CSGSFS",
		[REG_ERR] = "REG_ERR",
		[REG_TRAPNO] = "REG_TRAPNO",
		[REG_OLDMASK] = "REG_OLDMASK",
		[REG_CR2] = "REG_CR2"
	};
	return regs[regno];
}
#endif

int single_step(uint8_t *ip, mcontext_t *context, void *address)
{
	int is_write, ret;
	struct opcode_str *op;

	is_write = !!(context->gregs[REG_ERR] & 2);

	op = disassemble_insn_at(ip);
	assert(op);

	ret = op->asm_len;

	if (1) {
		struct location *src_l;
		struct location *dest_l;
		unsigned long *src_p;
		unsigned long *dest_p;
		int size;
		int8_t *d, *s;

		src_l = str_to_location(op->src);
		assert(src_l);
		dest_l = str_to_location(op->dest);
		assert(dest_l);

		src_p = (void *)get_val_addr(src_l, context);
		dest_p = (void *)get_val_addr(dest_l, context);

#define SOFFSET(x) ((x->has_soffset) ? (x->soffset) : 0)
#define DOFFSET(x) ((x->has_doffset) ? (x->doffset) : 0)

		size = src_l->size > dest_l->size ? dest_l->size : src_l->size;
		d = ((int8_t *)dest_p) + DOFFSET(op);
		s = ((int8_t *)src_p) + SOFFSET(op);
#if 0
		printf("rip: %p,  rax: %p\n", (void *)context->gregs[REG_RIP], (void *)context->gregs[REG_RAX]);
		printf("src : reg: %s, soffset: 0x%llx\n", regname(src_l->reg_no), SOFFSET(op));
		printf("dest: reg: %s, doffset: 0x%llx\n", regname(dest_l->reg_no), DOFFSET(op));
#endif
		switch (size) {
		case 64:
			d[8] = s[8];
			d[7] = s[7];
			d[6] = s[6];
			d[4] = s[4];
		case 32:
			d[3] = s[3];
			d[2] = s[2];
		case 16:
			d[1] = s[1];
		case 8:
			d[0] = s[0];
			break;
		default:
			assert(size != size);
		}
		free(src_l);
		free(dest_l);
	}
#if 0
	switch (*ip) {
	/* mov */
	case 0x89:
		++ip;
		switch (*ip) {
		case 0x02:
			*(uint32_t *)address = context->gregs[REG_RAX];
			return 2;
		default:
			fprintf(stderr, "Unknown opcode: 0x%02x\n", *ip);
			assert(0);
		}
	/* mov */
	case 0x8b:
		++ip;
		switch (*ip) {
		case 0x35:
			context->gregs[REG_RSI] = *(uint32_t *)address;
			return 6;
		default:
			fprintf(stderr, "Unknown opcode: 0x%02x\n", *ip);
			assert(0);
		}
	/* MOV 	rAX 	 moffs16/32/64 */
	case 0xa1:
		context->gregs[REG_RAX] = *(uint32_t *)address;
		return 5;
	/* MOV r/m16/32/64 imm16/32 */
	case 0xc7:
		++ip;
		switch (*ip) {
		case 0x00:
			context->gregs[REG_RAX] = *(uint32_t *)address;
			return 6;
		default:
			fprintf(stderr, "Unknown opcode: 0x%02x\n", *ip);
			assert(0);
		}
	default:
		fprintf(stderr, "Unknown opcode: 0x%02x\n", *ip);
		assert(0);
	}
	return -1;
#endif
	free(op);
	return ret;
}

#ifdef OPCODE_TEST

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

int main()
{
	int i;
	unsigned char opcodes[][5] = {
		{ 0x8b, 0x45, 0xfc },			/* mov -0x4(%rbp),%eax */
		{ 0x6b,0x7f, 0x9a, 0x7c },        	/* imul   $0x7c,-0x66(%edi),%edi*/
		{ 0xb9,0x8d, 0xf1, 0x0e, 0xd9 },  	/* mov    $0xd90ef18d,%ecx*/
		{ 0x71,0x58 },                  	/* jno    80482d7 <_init-0x415>*/
		{ 0x1c,0xac },                		/* sbb    $0xac,%al*/
		{ 0x4b },                  		/* dec    %ebx*/
		{ 0xe3,0xc0 },                  	/* jecxz  8048244 <_init-0x4a8>*/
		{ 0xbb,0xe3, 0x92, 0x7c, 0x66 },   	/* mov    $0x667c92e3,%ebx*/
		{ 0x07 },                    		/* pop    %es*/
		{ 0xb6,0x7a },                  	/* mov    $0x7a,%dh*/
		{ 0x6b,0x09, 0x43 }             	/* imul   $0x43,(%ecx),%ecx*/
	};


	for (i = 0; i < ARRAY_SIZE(opcodes); i++) {
		struct opcode_str *op;

		op = disassemble_insn_at(opcodes[i]);
		printf("opcode: [%s]\nsrc: [%s]\ndest: [%s]\n", op->opcode, op->src, op->dest);

	}
	return 0;
}

#endif
