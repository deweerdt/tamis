#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <ucontext.h>

#if defined(__i386__)
#define REG_RAX REG_EAX
#define REG_RSI REG_ESI
#endif

int single_step(uint8_t *ip, mcontext_t *context, void *address)
{
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
}

#if 0
7     6 5       3 2     0
  mod     dest      src 

mod: 
http://www.swansontec.com/sintel.htm
00	[src]	The operand s memory address is in src.
01	[src + byte]	The operand s memory address is src + a byte-sized displacement.
10	[src + word]	The operand s memory address is src + a word-sized displacement.
11	src	The operand is reg1 itself.

reg1:

#endif

enum {
	EAX = 0,
	ECX = 1,
	EDX = 2,
	EBX = 3,
	ESP = 4,
	EBP = 5,
	ESI = 6,
	EDI = 7
};
/* mod parsing */
#define mod_bits(x) 			(x & 0xc0)
#define to_mod_bits(x)  		(x << 6)
#define dest_bits(x) 			(x & 0x38)
#define to_dest_bits(x)  		(x << 3)
#define src_bits(x) 			(x & 0x07)

#define is_load_indirect(x) 		(mod_bits(x) == to_mod_bits(0))
#define is_load_indirect_byte_offset(x) (mod_bits(x) == to_mod_bits(1))
#define is_load_indirect_word_offset(x) (mod_bits(x) == to_mod_bits(2))
#define is_load_direct(x) 		(mod_bits(x) == to_mod_bits(3))

#define has_sib				(dest_bits(x) == to_dest_bit(ESP))


#ifdef OPCODE_TEST
int main()
{
	char opcode1[] = { 0x8b, 0x45, 0xfc };		/* mov -0x4(%rbp),%eax */
	char opcode2[] = { 0x89, 0x02 }; 		/* mov %eax,(%rdx) */


	return 0;
}
#endif
