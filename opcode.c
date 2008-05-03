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
	/* mov */
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
