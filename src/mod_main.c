#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/random.h>
#include <kputils.h>
#include <asm/current.h>
#include <asm/ptrace.h>

#include "mod_main.h"

KPM_NAME("feature");
KPM_VERSION("1.0.0");
KPM_AUTHOR("yuuki");
KPM_DESCRIPTION("hide features in mounts and maps | args {hook, unhook}");

// 필터링할 키워드 목록 (libart.so, bytehook 등 추가)
static struct filter_keyword filter_keywords[MAX_FILTER_KEYWORDS] = {
        { .keyword = "adb", .len = 0 },
        { .keyword = "module", .len = 0 },
        { .keyword = "libart.so", .len = 0 },
        { .keyword = "bytehook", .len = 0 },
        { .keyword = "trampoline", .len = 0 },
        { .keyword = "frida", .len = 0 },
        { .keyword = "xposed", .len = 0 },
};
static size_t num_keywords = 7;

// seq_file 구조체 정의 (헤더 누락 대비)
#ifndef SEQ_FILE_DEFINED
struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
};
#endif

static void *(*kf_vmalloc)(unsigned long size);
static void (*kf_vfree)(const void *addr);
static struct mm_struct *(*kf_get_task_mm)(struct task_struct *task);

// 후킹 대상 함수 주소 저장
static void *funcs[5];
static bool g_hooked = false;

static inline void print_info(void) {
    pr_info("Kernel Version: %x, Patch Version: %x\n", kver, kpver);
}

static inline bool is_proc_effective(void) {
    return kf_get_task_mm && current && kf_get_task_mm(current);
}

// 커널용 안전한 문자열 길이 측정
static size_t str_len_safe(const char *s) {
    const volatile char *p;
    size_t len = 0;
    if (!s) return 0;
    p = (const volatile char *)s;
    while (p[len]) len++;
    return len;
}

// 커널용 문자열 검색 (strstr 대체)
static char *kpm_strstr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;
    for (; *haystack; ++haystack) {
        if (*haystack == *needle) {
            const char *h = haystack;
            const char *n = needle;
            while (*h && *n && *h == *n) { h++; n++; }
            if (!*n) return (char *)haystack;
        }
    }
    return NULL;
}

// 커널용 문자열 검색 (strnstr 대체)
static char *kpm_strnstr(const char *haystack, const char *needle, size_t len) {
    if (!haystack || !needle) return NULL;
    if (!*needle) return (char *)haystack;
    for (size_t i = 0; i < len && haystack[i]; ++i) {
        if (haystack[i] == *needle) {
            size_t j = 1;
            while (j < (len - i) && needle[j] && haystack[i+j] == needle[j]) {
                j++;
            }
            if (!needle[j]) return (char *)(haystack + i);
        }
    }
    return NULL;
}

// 커널용 문자열 비교 (strcmp 대체)
static bool kpm_str_eq_lit(const char *s, const char *lit) {
    if (!s || !lit) return false;
    while (*s && *lit && *s == *lit) { s++; lit++; }
    return *s == '\0' && *lit == '\0';
}

static char get_random_char(void) {
    return RANDOM_CHARS[get_random_u64() % RANDOM_CHARS_LEN];
}

static void replace_sensitive(char *str, size_t len, const struct filter_keyword *keyword) {
    char *pos;
    while ((pos = kpm_strnstr(str, keyword->keyword, len)) != NULL) {
        size_t offset = pos - str;
        for (size_t i = 0; i < keyword->len && (offset + i < len); i++) {
            if (keyword->keyword[i] != '/' || str[offset + i] != '/') {
                str[offset + i] = get_random_char();
            }
        }
        str += offset + keyword->len;
        len -= offset + keyword->len;
    }
}

static inline bool contains_keyword(char *str, size_t len) {
    for (size_t i = 0; i < num_keywords; i++) {
        if (kpm_strnstr(str, filter_keywords[i].keyword, len)) {
            return true;
        }
    }
    return false;
}

static inline bool filter_output(struct seq_file *m, size_t old_count, bool replace) {
    if (!m || m->count <= old_count) return false;

    char *buf_start = m->buf + old_count;
    size_t len = m->count - old_count;

    if (contains_keyword(buf_start, len)) {
        if (replace) {
            for (size_t i = 0; i < num_keywords; i++) {
                replace_sensitive(buf_start, len, &filter_keywords[i]);
            }
        } else {
            m->count = old_count; // 라인 삭제
        }
        return true;
    }
    return false;
}

/* --- Hook Callbacks --- */
static void before_common(hook_fargs2_t *a, void *u) {
    a->local.data0 = 0;
    if (!is_proc_effective()) return;
    
    // 🟢 타겟팅 필터 (틱톡, 틱톡 라이트, 덕디텍터, Zygote 모두 포함)
    const char *comm = get_task_comm(current);
    if (!comm) return;
    
    bool is_target = (kpm_strstr(comm, "detector") != NULL) ||
                     (kpm_strstr(comm, "duckdetector") != NULL) ||
                     (kpm_strstr(comm, "zygote") != NULL) ||
                     (kpm_strstr(comm, "ss.android") != NULL) || // 틱톡/틱톡라이트
                     (kpm_strstr(comm, "tiktok") != NULL);       // 기타 틱톡
                     
    if (!is_target) return;

    struct seq_file *m = (struct seq_file *)a->arg0;
    if (m && m->buf) {
        a->local.data0 = m->count;
    }
}

static void after_vfsmnt(hook_fargs2_t *a, void *u) {
    if (!a->local.data0) return;
    struct seq_file *m = (struct seq_file *)a->arg0;
    if ((int)a->ret == 0) filter_output(m, a->local.data0, false);
}

static void after_mountinfo(hook_fargs2_t *a, void *u) {
    if (!a->local.data0) return;
    struct seq_file *m = (struct seq_file *)a->arg0;
    if ((int)a->ret == 0) filter_output(m, a->local.data0, true);
}

static void after_vfsstat(hook_fargs2_t *a, void *u) {
    if (!a->local.data0) return;
    struct seq_file *m = (struct seq_file *)a->arg0;
    if ((int)a->ret == 0) filter_output(m, a->local.data0, false);
}

static void after_map_vma(hook_fargs2_t *a, void *u) {
    if (!a->local.data0) return;
    struct seq_file *m = (struct seq_file *)a->arg0;
    filter_output(m, a->local.data0, false);
}

static void after_smap(hook_fargs2_t *a, void *u) {
    if (!a->local.data0) return;
    struct seq_file *m = (struct seq_file *)a->arg0;
    if ((int)a->ret == 0) filter_output(m, a->local.data0, false);
}

/* --- Install / Uninstall --- */
static bool hook_all(void) {
    if (g_hooked) return true;

    if (funcs[0]) hook_wrap(funcs[0], 2, before_common, after_vfsmnt, NULL);
    if (funcs[1]) hook_wrap(funcs[1], 2, before_common, after_mountinfo, NULL);
    if (funcs[2]) hook_wrap(funcs[2], 2, before_common, after_vfsstat, NULL);
    if (funcs[3]) hook_wrap(funcs[3], 2, before_common, after_map_vma, NULL);
    if (funcs[4]) hook_wrap(funcs[4], 2, before_common, after_smap, NULL);

    g_hooked = true;
    pr_info("[yuuki] hook installed...\n");
    return true;
}

static bool uninstall_hook(void) {
    if (!g_hooked) return true;
    
    if (funcs[0]) unhook(funcs[0]);
    if (funcs[1]) unhook(funcs[1]);
    if (funcs[2]) unhook(funcs[2]);
    if (funcs[3]) unhook(funcs[3]);
    if (funcs[4]) unhook(funcs[4]);

    g_hooked = false;
    pr_info("[yuuki] hook uninstalled...\n");
    return true;
}

/* --- KPM Init & Control --- */
static long mod_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[yuuki] Initializing...\n");
    print_info();

    for (size_t i = 0; i < num_keywords; i++) {
        filter_keywords[i].len = str_len_safe(filter_keywords[i].keyword);
    }

    static const char *syms[] = {"show_vfsmnt", "show_mountinfo", "show_vfsstat", "show_map_vma", "show_smap"};
    for (int i = 0; i < 5; i++) {
        funcs[i] = (void *)kallsyms_lookup_name(syms[i]);
        if (!funcs[i]) {
            pr_err("[yuuki] symbol %s not found\n", syms[i]);
        }
    }

    kf_vmalloc = (void *)kallsyms_lookup_name("vmalloc");
    kf_vfree = (void *)kallsyms_lookup_name("vfree");
    kf_get_task_mm = (void *)kallsyms_lookup_name("get_task_mm");

    return 0;
}

static long mod_control0(const char *args, char *__user out_msg, int outlen) {
    pr_info("[yuuki] kpm_control0, args: %s\n", args);

    if (kpm_str_eq_lit(args, "hook")) {
        hook_all();
        compat_copy_to_user(out_msg, "hooked\n", 7);
    } else if(kpm_str_eq_lit(args, "unhook")) {
        uninstall_hook();
        compat_copy_to_user(out_msg, "unhooked\n", 9);
    } else {
        char echo[64] = "unknown: ";
        compat_copy_to_user(out_msg, echo, sizeof(echo));
    }
    return 0;
}

static long mod_exit(void *__user reserved) {
    uninstall_hook();
    pr_info("[yuuki] mod_exit, uninstalled hook.\n");
    return 0;
}

KPM_INIT(mod_init);
KPM_CTL0(mod_control0);
KPM_EXIT(mod_exit);
