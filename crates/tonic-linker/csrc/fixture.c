/* Synthetic ELF fixture for the loader. Built with -nostdlib: every external
 * symbol below is undefined in the object and must be resolved by the host
 * symbol provider. It deliberately exercises:
 *
 *   - PT_LOAD mapping (code + r/o data + init_array)
 *   - R_X86_64_JUMP_SLOT for the PLT call to fixture_probe_mark
 *   - R_X86_64_64 for the fixture_mark_ptr data relocation
 *   - R_X86_64_TPOFF64 for the initial-exec TLS variable (applied, not read)
 *   - DT_INIT_ARRAY constructor, which calls back into the host
 *   - DT_FINI_ARRAY destructor, recorded for a later stage
 *
 * It is NOT Roblox. libroblox.so is 116 MB of foreign code and is never
 * vendored into this repository. */

extern int fixture_probe_mark(const char *what);

/* initial-exec keeps the TLS model static, so the linker emits a TPOFF64
 * relocation instead of a call to __tls_get_addr (which we do not provide). */
__thread int fixture_tls_counter
    __attribute__((tls_model("initial-exec"), used)) = 3;

/* A data relocation: the address of an imported function stored in .data. */
int (*fixture_mark_ptr)(const char *) __attribute__((used)) = fixture_probe_mark;

int fixture_add(int a, int b) {
    return a + b;
}

/* Kept out of fixture_add on purpose: touching TLS at run time needs a
 * bionic-shaped thread pointer, which is M2 work. */
int fixture_tls_offset(void) {
    return (int)((char *)&fixture_tls_counter - (char *)0);
}

__attribute__((constructor)) static void fixture_ctor(void) {
    fixture_probe_mark("ctor");
}

__attribute__((destructor)) static void fixture_dtor(void) {
    fixture_probe_mark("dtor");
}
