#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdint.h> // For uintptr_t

// --- XOR Obfuscation ---
// Obfuscated name for g_data_transform_key (must match kernel module)
static const unsigned char g_secret_seq_const[] = {0x5A, 0xA5, 0x3C, 0xC3, 0xF0, 0x0F, 0xAA, 0x55};

// Shared secret for authentication (obfuscated name: g_channel_auth_sequence)
static const unsigned char __attribute__((unused)) g_channel_auth_sequence[] = {
    0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81,
    0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09
};

// Obfuscated name for transform_data_buffer (must match kernel module)
static void transform_data_buffer(unsigned char *buffer_addr, size_t buffer_len) {
    size_t key_len = sizeof(g_secret_seq_const);
    size_t i;
    for (i = 0; i < buffer_len; ++i) {
        buffer_addr[i] = buffer_addr[i] ^ g_secret_seq_const[i % key_len];
    }
}
// --- End XOR Obfuscation ---

// --- IPC 通道协议和消息结构定义 (必须与内核组件一致) ---
#define CTL_CHANNEL_ID 29     // IPC 通道协议ID (原 NETLINK_MY_PROTOCOL, 值从31更改为29)
#define REQ_TYPE_QUERY_BASE 1 // 获取区域基地址请求 (原 MSG_TYPE_GET_MODULE_BASE)
#define REQ_TYPE_FETCH_PTR 2    // 读取 uintptr_t 类型数据请求 (原 MSG_TYPE_READ_UINTPTR)
#define REQ_TYPE_FETCH_INT 3        // 读取 int 类型数据请求 (原 MSG_TYPE_READ_INT)
#define RESP_TYPE_ERROR_STATUS 4           // 错误消息类型 (内核返回, 原 MSG_TYPE_ERROR)

// 上行消息结构体 (用户空间到内核)
typedef struct {
    int type;             // 消息类型
    pid_t target_id;      // 目标进程ID (原 pid)
    uintptr_t data_offset; // 读取操作的目标地址 (原 address)
    char object_label[128]; // 区域标签 (原 name)
    unsigned char auth_key_data[16]; // New field for the token (size matches secret)
} ipc_msg_upstream_t; // 原 nl_request_t

// 下行消息结构体 (内核到用户空间)
typedef struct {
    int type;             // 响应类型
    uintptr_t value;      // 读取结果或基地址
    int error_code;       // 错误码 (0 表示成功)
} ipc_msg_downstream_t; // 原 nl_response_t

// --- 全局变量 ---
static int g_ipc_descriptor = -1; // IPC 通道描述符 (原 nl_sock_fd)

// --- IPC 通信辅助函数 ---

/**
 * @brief 执行IPC事务 (发送请求并接收响应)
 *
 * @param up_payload 指向 ipc_msg_upstream_t 结构的指针，包含要发送的请求数据
 * @param down_payload 指向 ipc_msg_downstream_t 结构的指针，用于存储内核的响应
 * @return int 0 表示成功，-1 表示本地错误，或者内核返回的错误码 (负数)
 */
static int execute_ipc_transaction(ipc_msg_upstream_t *up_payload, ipc_msg_downstream_t *down_payload) { // 原 send_receive_nl_msg
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    ssize_t recv_len;

    if (g_ipc_descriptor < 0) {
        fprintf(stderr, "错误: IPC描述符未初始化。\n");
        return -1;
    }

    // 准备上行消息头
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(ipc_msg_upstream_t)));
    if (!nlh) {
        perror("错误: 分配IPC消息头失败");
        return -1;
    }
    memset(nlh, 0, NLMSG_SPACE(sizeof(ipc_msg_upstream_t)));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(ipc_msg_upstream_t));
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;

    // Encrypt/Obfuscate outgoing payload before copying to Netlink message
    transform_data_buffer((unsigned char *)up_payload, sizeof(ipc_msg_upstream_t)); // XOR obfuscation re-enabled

    // 复制请求数据到消息体
    memcpy(NLMSG_DATA(nlh), up_payload, sizeof(ipc_msg_upstream_t));

    // 设置目标地址 (内核)
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    // 设置 iovec
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    // 设置 msghdr
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // 发送消息
    // printf("调试: 发送类型为 %d 的IPC消息到内核, TargetID: %d, Offset: 0x%lx, Label: %s\n",
    //        up_payload->type, up_payload->target_id, up_payload->data_offset, up_payload->object_label);
    if (sendmsg(g_ipc_descriptor, &msg, 0) < 0) {
        perror("错误: sendmsg 发送IPC消息失败");
        free(nlh);
        return -1;
    }

    // 接收消息
    memset(nlh, 0, NLMSG_SPACE(sizeof(ipc_msg_upstream_t)));
    recv_len = recvmsg(g_ipc_descriptor, &msg, 0);
    if (recv_len < 0) {
        perror("错误: recvmsg 接收IPC响应失败");
        free(nlh);
        return -1;
    }

    if (NLMSG_OK(nlh, (unsigned int)recv_len)) {
        ipc_msg_downstream_t *kernel_response = (ipc_msg_downstream_t *)NLMSG_DATA(nlh);
        memcpy(down_payload, kernel_response, sizeof(ipc_msg_downstream_t));

        // Decrypt/Deobfuscate incoming response payload
        transform_data_buffer((unsigned char *)down_payload, sizeof(ipc_msg_downstream_t)); // XOR obfuscation re-enabled

        // printf("调试: 收到内核响应 (解密后): 类型=%d, 值=0x%lx, 错误码=%d\n",
        //        down_payload->type, down_payload->value, down_payload->error_code);

        if (down_payload->error_code != 0) {
            free(nlh);
            return down_payload->error_code;
        }
        free(nlh);
        return 0; // 成功
    } else {
        fprintf(stderr, "错误: 收到的IPC消息无效 (长度或类型问题)。recv_len=%zd, nlmsg_len=%u\n",
                recv_len, nlh->nlmsg_len);
        if (recv_len > 0 && nlh->nlmsg_type == NLMSG_ERROR) {
             struct nlmsgerr *nlerr = (struct nlmsgerr*)NLMSG_DATA(nlh);
             fprintf(stderr, "错误详情: IPC错误消息: %s (%d)\n", strerror(-nlerr->error), -nlerr->error);
             free(nlh);
             return nlerr->error;
        }
        free(nlh);
        return -1;
    }
}

// --- API 函数 ---

/**
 * @brief 获取目标进程中指定区域的基地址
 *
 * @param target_id 目标进程ID
 * @param object_label 要查找的区域标签
 * @return uintptr_t 区域的基地址，如果失败则返回 0
 */
uintptr_t query_target_base(pid_t target_id, const char* object_label) { // 原 getModuleBase
    ipc_msg_upstream_t up_payload;
    ipc_msg_downstream_t down_payload;
    int ret;

    memset(&up_payload, 0, sizeof(up_payload));
    up_payload.type = REQ_TYPE_QUERY_BASE;
    up_payload.target_id = target_id;
    strncpy(up_payload.object_label, object_label, sizeof(up_payload.object_label) - 1);
    memcpy(up_payload.auth_key_data, g_channel_auth_sequence, sizeof(up_payload.auth_key_data));

    printf("请求: 获取TargetID %d中区域 '%s' 的基地址。\n", target_id, object_label);
    ret = execute_ipc_transaction(&up_payload, &down_payload);
    if (ret == 0 && down_payload.error_code == 0) {
        printf("成功: 区域 '%s' (TargetID: %d) 的基地址为: 0x%lx\n", object_label, target_id, down_payload.value);
        return down_payload.value;
    } else {
        fprintf(stderr, "错误: 获取区域 '%s' (TargetID: %d) 基地址失败。通讯错误: %d, 内核错误: %d\n",
                object_label, target_id, ret, down_payload.error_code);
        return 0;
    }
}

/**
 * @brief 从目标进程的指定地址读取一个 uintptr_t 类型的值
 *
 * @param target_id 目标进程ID
 * @param data_offset 要读取的内存地址
 * @return uintptr_t 读取到的值，如果失败则返回 0
 */
uintptr_t fetch_remote_pointer(pid_t target_id, uintptr_t data_offset) { // 原 getzz
    ipc_msg_upstream_t up_payload;
    ipc_msg_downstream_t down_payload;
    int ret;

    if (data_offset == 0) {
        fprintf(stderr, "警告: fetch_remote_pointer 尝试从偏移 0x0 读取，这通常是无效的。\n");
    }

    memset(&up_payload, 0, sizeof(up_payload));
    up_payload.type = REQ_TYPE_FETCH_PTR;
    up_payload.target_id = target_id;
    up_payload.data_offset = data_offset;
    memcpy(up_payload.auth_key_data, g_channel_auth_sequence, sizeof(up_payload.auth_key_data));

    ret = execute_ipc_transaction(&up_payload, &down_payload);
    if (ret == 0 && down_payload.error_code == 0) {
        return down_payload.value;
    } else {
        fprintf(stderr, "错误: 从TargetID %d 偏移 0x%lx 读取指针失败。通讯错误: %d, 内核错误: %d\n",
                target_id, data_offset, ret, down_payload.error_code);
        return 0;
    }
}

/**
 * @brief 从目标进程的指定地址读取一个 int 类型的值
 *
 * @param target_id 目标进程ID
 * @param data_offset 要读取的内存地址
 * @return int 读取到的值，如果失败则返回 0
 */
int fetch_remote_integer(pid_t target_id, uintptr_t data_offset) { // 原 getint
    ipc_msg_upstream_t up_payload;
    ipc_msg_downstream_t down_payload;
    int ret;

    if (data_offset == 0) {
        fprintf(stderr, "警告: fetch_remote_integer 尝试从偏移 0x0 读取，这通常是无效的。\n");
    }

    memset(&up_payload, 0, sizeof(up_payload));
    up_payload.type = REQ_TYPE_FETCH_INT;
    up_payload.target_id = target_id;
    up_payload.data_offset = data_offset;
    memcpy(up_payload.auth_key_data, g_channel_auth_sequence, sizeof(up_payload.auth_key_data));

    ret = execute_ipc_transaction(&up_payload, &down_payload);
    if (ret == 0 && down_payload.error_code == 0) {
        return (int)down_payload.value;
    } else {
        fprintf(stderr, "错误: 从TargetID %d 偏移 0x%lx 读取整数失败。通讯错误: %d, 内核错误: %d\n",
                target_id, data_offset, ret, down_payload.error_code);
        return 0;
    }
}

// --- Main 函数 ---
int main(int argc, char *argv[]) {
    pid_t target_process_handle; // 原 target_pid
    uintptr_t core_region_base; // 原 game_core_base
    // uintptr_t core_data_offset; // 原 libGameCore_offset - REMOVED
    // uintptr_t val1, val2, entity_list_ptr, entity_prop_base; // 原 temp1, temp2, char_array_ptr, hp_ptr_base - REMOVED
    // int entity_id, entity_health; // 原 char_id, current_hp - REMOVED
    // int i = 0; - REMOVED

    struct sockaddr_nl src_addr;

    // if (argc < 2) { // PID is still required
    //     fprintf(stderr, "用法: %s <TargetHandle>\n", argv[0]);
    //     fprintf(stderr, "示例: %s 1234\n", argv[0]);
    //     return EXIT_FAILURE;
    // }

    // target_process_handle = atoi(argv[1]);
    target_process_handle = 12345; // 中文注释: <<-- 重要：请在此修改为您要测试的目标游戏进程的PID -->>
    printf("中文注释: 注意 - 正在使用代码中硬编码的目标进程PID: %d\n", target_process_handle);
    printf("中文注释: 如果需要测试不同进程，请直接修改 user_program.c 文件中的 target_process_handle 值。\n");

    if (target_process_handle <= 0) {
        fprintf(stderr, "错误: 无效的 TargetHandle (硬编码或修改后仍然无效): %d\n", target_process_handle);
        return EXIT_FAILURE;
    }

    const char* region_to_find = "libGameCore.so"; // Hardcoded region name

    // 1. 初始化 IPC 通道
    g_ipc_descriptor = socket(PF_NETLINK, SOCK_RAW, CTL_CHANNEL_ID);
    if (g_ipc_descriptor < 0) {
        perror("错误: 创建IPC描述符失败");
        return EXIT_FAILURE;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;

    if (bind(g_ipc_descriptor, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
        perror("错误: 绑定IPC描述符失败");
        close(g_ipc_descriptor);
        return EXIT_FAILURE;
    }
    printf("IPC 通道初始化成功 (fd: %d, pid: %d)。\n", g_ipc_descriptor, getpid());

    // 2. 演示 API 调用
    printf("\n--- 开始远程数据查询操作 (目标句柄: %d) ---\n", target_process_handle);

    // core_region_base = query_target_base(target_process_handle, region_to_find);
    core_region_base = 0x75CD840000; // 中文注释: GG修改器获取的 libGameCore.so 有效基址 (临时硬编码用于测试)
    printf("中文注释: 注意 - 使用硬编码的 libGameCore.so 基址: 0x%lx\n", core_region_base);
    if (core_region_base == 0) {
        fprintf(stderr, "关键错误: 未能获取区域 '%s' 的基地址，无法继续。\n", region_to_find);
        close(g_ipc_descriptor);
        return EXIT_FAILURE;
    }
    printf("获取到区域 '%s' 基地址: 0x%lx\n", region_to_find, core_region_base);

    // --- 新增 根据用户最新提供的偏移读取第一个实体的血量 ---
    printf("\n--- 开始根据最新偏移读取第一个实体的血量 ---\n");

    if (core_region_base != 0) { // 确保 libGameCore.so 基地址有效
        // 步骤 1: P1_val = ReadPointer(libGameCore.so + 0x161910)
        uintptr_t p1_addr = core_region_base + 0x161910;
        printf("中文注释: 计算 P1 指针的存储地址 (core_region_base + 0x161910) = 0x%lx\n", p1_addr);
        uintptr_t p1_val = fetch_remote_pointer(target_process_handle, p1_addr);
        if (p1_val == 0) {
            fprintf(stderr, "中文注释: 错误 - 读取 P1 指针值失败 (地址: 0x%lx)\n", p1_addr);
        } else {
            printf("中文注释: 成功 - 读取 P1 指针值 p1_val = 0x%lx\n", p1_val);

            // 步骤 2: P2_val = ReadPointer(P1_val + 0x238)
            uintptr_t p2_addr = p1_val + 0x238;
            printf("中文注释: 计算 P2 指针的存储地址 (p1_val + 0x238) = 0x%lx\n", p2_addr);
            uintptr_t p2_val = fetch_remote_pointer(target_process_handle, p2_addr);
            if (p2_val == 0) {
                fprintf(stderr, "中文注释: 错误 - 读取 P2 指针值失败 (地址: 0x%lx)\n", p2_addr);
            } else {
                printf("中文注释: 成功 - 读取 P2 指针值 p2_val = 0x%lx (此为实体指针数组的基址或包含它的结构体指针)\n", p2_val);

                // 步骤 3: Entity0_Base = ReadPointer(P2_val + i*0x18) ; i=0 for first entity
                // P2_val is now considered the base of the array (or structure containing it) of entity pointers.
                // For the first entity (i=0), the location of its pointer is P2_val itself.
                uintptr_t entity0_ptr_storage_addr = p2_val;
                printf("中文注释: 第一个实体的指针存储地址 (p2_val + 0*0x18) = 0x%lx\n", entity0_ptr_storage_addr);
                uintptr_t entity0_base = fetch_remote_pointer(target_process_handle, entity0_ptr_storage_addr);

                if (entity0_base == 0) {
                    fprintf(stderr, "中文注释: 错误 - 读取第一个实体的基址 entity0_base 失败 (从地址 0x%lx 读取)\n", entity0_ptr_storage_addr);
                } else {
                    printf("中文注释: 成功 - 读取到第一个实体的基址 entity0_base = 0x%lx\n", entity0_base);

                    // 步骤 4: 读取血量和最大血量
                    // Health_Struct_Ptr = ReadPointer(Entity0_Base + 0x168)
                    uintptr_t health_struct_ptr_addr = entity0_base + 0x168;
                    printf("中文注释: 计算健康结构体指针的存储地址 (entity0_base + 0x168) = 0x%lx\n", health_struct_ptr_addr);
                    uintptr_t health_struct_ptr_val = fetch_remote_pointer(target_process_handle, health_struct_ptr_addr);

                    if (health_struct_ptr_val == 0) {
                        fprintf(stderr, "中文注释: 错误 - 读取健康结构体指针值失败 (地址: 0x%lx)\n", health_struct_ptr_addr);
                    } else {
                        printf("中文注释: 成功 - 读取健康结构体指针值 health_struct_ptr_val = 0x%lx\n", health_struct_ptr_val);

                        // 当前血量 = ReadInteger(Health_Struct_Ptr + 0x98)
                        uintptr_t current_hp_addr = health_struct_ptr_val + 0x98;
                        int current_hp = fetch_remote_integer(target_process_handle, current_hp_addr);

                        // 最大血量 = ReadInteger(Health_Struct_Ptr + 0xA0)
                        uintptr_t max_hp_addr = health_struct_ptr_val + 0xA0;
                        int max_hp = fetch_remote_integer(target_process_handle, max_hp_addr);

                        printf("中文注释: 信息 - 实体 0 - 当前血量: %d, 最大血量: %d (当前HP地址=0x%lx, 最大HP地址=0x%lx)\n", current_hp, max_hp, current_hp_addr, max_hp_addr);
                    }
                }
            }
        }
    } else { // Corresponds to the if (core_region_base != 0) check
         fprintf(stderr, "中文注释: core_region_base (libGameCore.so 基址) 为0，跳过新偏移测试。\n");
    }
    printf("--- 最新偏移读取测试结束 ---\n\n");
    // --- 新增代码结束 ---

    // 3. 关闭 IPC 通道
    if (g_ipc_descriptor >= 0) {
        close(g_ipc_descriptor);
        printf("\nIPC 通道已关闭。\n");
    }

    return EXIT_SUCCESS;
}
