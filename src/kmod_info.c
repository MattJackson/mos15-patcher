#include <mach/mach_types.h>

extern kern_return_t mp_start(kmod_info_t *ki, void *data);
extern kern_return_t mp_stop(kmod_info_t *ki, void *data);

__attribute__((visibility("default")))
KMOD_EXPLICIT_DECL(com.docker-macos.kext.mos15Patcher, "1.0.0", mp_start, mp_stop)
__attribute__((used, section("__DATA,__kmod_info")));
