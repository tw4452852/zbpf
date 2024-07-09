#ifndef __LIBBPF_LIBBPF_ITER_H
#define __LIBBPF_LIBBPF_ITER_H

enum btf_field_iter_kind {
	BTF_FIELD_ITER_IDS,
	BTF_FIELD_ITER_STRS,
};

struct btf_field_desc {
	/* once-per-type offsets */
	int t_off_cnt, t_offs[2];
	/* member struct size, or zero, if no members */
	int m_sz;
	/* repeated per-member offsets */
	int m_off_cnt, m_offs[1];
};

struct btf_field_iter {
	struct btf_field_desc desc;
	void *p;
	int m_idx;
	int off_idx;
	int vlen;
};

int btf_field_iter_init(struct btf_field_iter *it, struct btf_type *t, enum btf_field_iter_kind iter_kind);
__u32 *btf_field_iter_next(struct btf_field_iter *it);

#endif /* __LIBBPF_LIBBPF_ITER_H */