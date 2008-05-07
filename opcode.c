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
#include <ucontext.h>
#include <stdarg.h>


#if defined(__i386__)
#define REG_RAX REG_EAX
#define REG_RBX REG_EBX
#define REG_RCX REG_ECX
#define REG_RDX REG_EDX
#define REG_RSI REG_ESI
#endif

struct opcode_str {
	char opcode[32];
	char src[32];
	char dest[32];
	int asm_len;
};

static struct opcode_str *parse_disassembly(char *str)
{
	struct opcode_str *op;
	char *p = str, *d;
	int first_comma = 1;

	op = calloc(1, sizeof(*op));
	if (!op)
		return NULL;

	d = op->opcode;
	do {
		if (*p == ' ') {
			*d = '\0';
			d = op->src;
			/* skip extraneaous whitespaces */
			while (*p == ' ')
				p++;
		}
		if (*p == ',' && first_comma) {
			*d = '\0';
			d = op->dest;
			p++;
			first_comma = 0;
		}
		*d++ = *p++;
	} while(*p);

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
};
static struct location *str_to_location(const char *str)
{
	struct location *l;

	l = malloc(sizeof(*l));
	if (!l)
		return NULL;

	while ((*str == '%' || *str == '('
	        || *str == 'e') && *str != '\0' )
		str++;

	if (*str == '\0')
		return NULL;

	/* immediate value */
	if (*str == '$') {
		l->type = IMMEDIATE;
		l->immediate = strtol(str + 1, NULL, 0);
		goto out;
	}

	/* address value */
	if (*str == '0' && *(str + 1) == 'x') {
		l->type = ADDRESS;
		l->address = strtol(str, NULL, 0);
		goto out;
	}

	/* register */
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
	}

	abort();
out:
	return l;
}

int32_t *get_val_addr(struct location *l, mcontext_t *context)
{
	int32_t *ret = NULL;
	switch (l->type) {
	case REGISTER:
		ret = &context->gregs[l->reg_no];
		break;
	case IMMEDIATE:
		ret = (void *)&l->immediate;
		break;
	case ADDRESS:
		ret = (void *)l->address;
		break;
	default:
		abort();
	}
	return ret;
}
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
		int32_t *src_p;
		int32_t *dest_p;

		src_l = str_to_location(op->src);
		assert(src_l);
		dest_l = str_to_location(op->dest);
		assert(dest_l);

		src_p = get_val_addr(src_l, context);
		dest_p = get_val_addr(dest_l, context);

		*dest_p = *src_p;

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
