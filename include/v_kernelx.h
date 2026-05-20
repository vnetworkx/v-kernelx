#ifndef V_KERNELX_H
#define V_KERNELX_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(_WIN64)
  #ifdef V_KERNELX_EXPORTS
    #define V_KERNELX_API __declspec(dllexport)
  #else
    #define V_KERNELX_API __declspec(dllimport)
  #endif
#else
  #define V_KERNELX_API
#endif

#include <stddef.h>

typedef void* v_kernelx_handle;

/*
 * Lifecycle
 */
V_KERNELX_API v_kernelx_handle kernel_init(void);
V_KERNELX_API void kernel_free(v_kernelx_handle handle);

/*
 * Error handling
 * Returns a null-terminated UTF-8 string owned by Rust.
 * Caller must release it with kernel_string_free().
 */
V_KERNELX_API char* kernel_last_error(v_kernelx_handle handle);
V_KERNELX_API void kernel_string_free(char* s);

/*
 * Canonical operations
 * Each function accepts a JSON request string and returns a JSON response string.
 * The returned string is owned by Rust and must be freed with kernel_string_free().
 */
V_KERNELX_API char* kernel_validate_event(const char* input_json);
V_KERNELX_API char* kernel_submit_event(v_kernelx_handle handle, const char* input_json);
V_KERNELX_API char* kernel_execute_operation(v_kernelx_handle handle, const char* input_json);
V_KERNELX_API char* kernel_replay(v_kernelx_handle handle);
V_KERNELX_API char* kernel_compute_state_root(v_kernelx_handle handle);
V_KERNELX_API char* kernel_current_state_root(v_kernelx_handle handle);
V_KERNELX_API char* kernel_verify_record(v_kernelx_handle handle, const char* input_json);
V_KERNELX_API char* kernel_verify_signature(const char* input_json);

/*
 * Optional helpers
 */
V_KERNELX_API char* kernel_origin_create(v_kernelx_handle handle, const char* request_json);
V_KERNELX_API char* kernel_transfer(v_kernelx_handle handle, const char* request_json);
V_KERNELX_API char* kernel_drain(v_kernelx_handle handle, const char* request_json);
V_KERNELX_API char* kernel_project(v_kernelx_handle handle, const char* request_json);
V_KERNELX_API char* kernel_reconstruct(v_kernelx_handle handle, const char* request_json);
V_KERNELX_API char* kernel_certify(v_kernelx_handle handle, const char* request_json);
V_KERNELX_API char* kernel_query_vector(v_kernelx_handle handle, const char* request_json);
V_KERNELX_API char* kernel_query_vectors(v_kernelx_handle handle, const char* request_json);
V_KERNELX_API char* kernel_query_records(v_kernelx_handle handle, const char* request_json);
V_KERNELX_API char* kernel_query_event_by_hash(v_kernelx_handle handle, const char* request_json);

#ifdef __cplusplus
}
#endif

#endif /* V_KERNELX_H */