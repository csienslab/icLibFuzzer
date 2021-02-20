#ifndef _COMMON_DEF_H
#define _COMMON_DEF_H
#define ATTRIBUTE_INTERFACE __attribute__((visibility("default")))
#define ATTRIBUTE_TARGET_POPCNT __attribute__((target("popcnt")))
#define ATTRIBUTE_NO_SANITIZE_ADDRESS __attribute__((no_sanitize_address))
#define ATTRIBUTE_NO_SANITIZE_ALL ATTRIBUTE_NO_SANITIZE_ADDRESS
#endif
