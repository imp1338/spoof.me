#pragma once
#include <export/exports.hxx>

#define log_info(format, ...) \
    dbg_caller::dbg_print(format "\n", __VA_ARGS__)

#define log_error(format, ...) \
    dbg_caller::dbg_print("[Impala] : (Error) ->  " format "\n", __VA_ARGS__)

#define log_success(format, ...) \
    dbg_caller::dbg_print("[Impala] : (Success) ->  " format "\n", __VA_ARGS__)

#define log_warning(format, ...) \
    dbg_caller::dbg_print("[Impala] : (Warning) -> " format "\n", __VA_ARGS__)

#define log_info_simple(message) \
    dbg_caller::dbg_print(message "\n")

#define log_error_simple(message) \
    dbg_caller::dbg_print("[Impala] : (Error) ->  " message "\n")

#define log_success_simple(message) \
    dbg_caller::dbg_print("[Impala] : (Success) ->  " message "\n")