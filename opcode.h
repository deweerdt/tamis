#ifndef _OPCODE_H_
#define _OPCODE_H_

int single_step(uint8_t *ip, mcontext_t *context, void *value);

#endif /* _OPCODE_H_ */
