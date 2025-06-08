#ifndef KERNEL_NETLINK_INTERFACE_H
#define KERNEL_NETLINK_INTERFACE_H

#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdint.h> // For uintptr_t
#include <unistd.h> // For getpid()
#include <string.h> // For memcpy, strncpy, memset
#include <stdlib.h> // For malloc, free
#include <stdio.h>  // For perror, fprintf, stderr

// --- XOR Obfuscation (from user_program.c) ---
// Obfuscated name for g_data_transform_key (must match kernel module)
static const unsigned char g_netlink_secret_seq_const[] = {0x5A, 0xA5, 0x3C, 0xC3, 0xF0, 0x0F, 0xAA, 0x55};

// Shared secret for authentication (obfuscated name: g_channel_auth_sequence)
static const unsigned char g_netlink_channel_auth_sequence[] = {
    0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81,
    0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09
};

// Obfuscated name for transform_data_buffer (must match kernel module)
static inline void netlink_transform_data_buffer(unsigned char *buffer_addr, size_t buffer_len) {
    size_t key_len = sizeof(g_netlink_secret_seq_const);
    size_t i;
    for (i = 0; i < buffer_len; ++i) {
        buffer_addr[i] = buffer_addr[i] ^ g_netlink_secret_seq_const[i % key_len];
    }
}
// --- End XOR Obfuscation ---

// --- IPC 通道协议和消息结构定义 (必须与内核组件一致) (from user_program.c) ---
#define NETLINK_CTL_CHANNEL_ID 29     // IPC 通道协议ID
#define NETLINK_REQ_TYPE_QUERY_BASE 1 // 获取区域基地址请求
#define NETLINK_REQ_TYPE_FETCH_PTR 2    // 读取 uintptr_t 类型数据请求
#define NETLINK_REQ_TYPE_FETCH_INT 3    // 读取 int 类型数据请求
// Define new types for writing data if we implement it later
#define NETLINK_REQ_TYPE_WRITE_PTR 5  // 写入 uintptr_t 类型数据请求
#define NETLINK_REQ_TYPE_WRITE_INT 6  // 写入 int 类型数据请求

#define NETLINK_RESP_TYPE_ERROR_STATUS 4 // 错误消息类型 (内核返回)


// 上行消息结构体 (用户空间到内核) (from user_program.c)
typedef struct {
    int type;             // 消息类型
    pid_t target_id;      // 目标进程ID
    uintptr_t data_offset; // 读取/写入操作的目标地址
    char object_label[128]; // 区域标签
    unsigned char auth_key_data[16]; // Authentication token
    unsigned long value_to_write; // Used for write operations
} netlink_ipc_msg_upstream_t;

// 下行消息结构体 (内核到用户空间) (from user_program.c)
typedef struct {
    int type;             // 响应类型
    uintptr_t value;      // 读取结果或基地址
    int error_code;       // 错误码 (0 表示成功)
} netlink_ipc_msg_downstream_t;


// Global IPC descriptor for Netlink
extern int g_netlink_ipc_descriptor;

// Function prototypes for Netlink communication
// Implementation will be in a .cpp file (likely the refactored c_driver.cpp)

/**
 * @brief Initializes the Netlink socket for communication with the kernel module.
 * @return int 0 on success, -1 on failure.
 */
int initialize_netlink_connection();

/**
 * @brief Closes the Netlink socket.
 */
void close_netlink_connection();

/**
 * @brief 执行IPC事务 (发送请求并接收响应)
 *
 * @param up_payload 指向 netlink_ipc_msg_upstream_t 结构的指针，包含要发送的请求数据
 * @param down_payload 指向 netlink_ipc_msg_downstream_t 结构的指针，用于存储内核的响应
 * @return int 0 表示成功，-1 表示本地错误，或者内核返回的错误码 (负数)
 */
int execute_netlink_ipc_transaction(netlink_ipc_msg_upstream_t *up_payload, netlink_ipc_msg_downstream_t *down_payload);

#endif // KERNEL_NETLINK_INTERFACE_H
