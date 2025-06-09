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
    uintptr_t core_data_offset; // 原 libGameCore_offset
    uintptr_t val1, val2, entity_list_ptr, entity_prop_base; // 原 temp1, temp2, char_array_ptr, hp_ptr_base
    int entity_id, entity_health; // 原 char_id, current_hp
    int i = 0;

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

    core_region_base = query_target_base(target_process_handle, region_to_find);
    if (core_region_base == 0) {
        fprintf(stderr, "关键错误: 未能获取区域 '%s' 的基地址，无法继续。\n", region_to_find);
        close(g_ipc_descriptor);
        return EXIT_FAILURE;
    }
    printf("获取到区域 '%s' 基地址: 0x%lx\n", region_to_find, core_region_base);

    // --- 新增 直接读取您在GG修改器中找到的特定地址的值 ---
    uintptr_t gg_address_to_read = 0x74EE4F49D0; // 您提供的地址
    printf("\n--- 开始直接读取GG提供的特定地址 (0x%lx) ---\n", gg_address_to_read);

    // 尝试1: 假设该地址是一个整数 (int, 通常4字节)
    printf("中文注释: 尝试将地址 0x%lx 读取为整数 (int)...\n", gg_address_to_read);
    int gg_int_value = fetch_remote_integer(target_process_handle, gg_address_to_read);
    // execute_ipc_transaction (called within fetch_remote_integer) will print detailed errors if any.
    printf("中文注释: 读取地址 0x%lx 作为整数的结果: %d (十进制), 0x%x (十六进制)\n", gg_address_to_read, gg_int_value, gg_int_value);
    if (gg_int_value == 0 && gg_address_to_read != 0) {
        // This is a general note, as fetch_remote_integer returns 0 on error OR if the actual value is 0.
        // Detailed errors would have been printed by execute_ipc_transaction to stderr.
        fprintf(stderr, "中文注释: 注意 - 若整数结果为0，请检查之前是否有通讯或内核错误信息。这可能是真实值为0，也可能是读取失败。\n");
    }

    // 尝试2: 假设该地址是一个指针大小的值 (uintptr_t, 通常8字节)
    printf("中文注释: 尝试将地址 0x%lx 读取为指针大小的值 (uintptr_t)...\n", gg_address_to_read);
    uintptr_t gg_ptr_value = fetch_remote_pointer(target_process_handle, gg_address_to_read);
    // execute_ipc_transaction (called within fetch_remote_pointer) will print detailed errors if any.
    printf("中文注释: 读取地址 0x%lx 作为指针大小值的结果: 0x%lx\n", gg_address_to_read, gg_ptr_value);
    if (gg_ptr_value == 0 && gg_address_to_read != 0) {
        // Similar note for pointer-sized value.
        fprintf(stderr, "中文注释: 注意 - 若指针大小值结果为0，请检查之前是否有通讯或内核错误信息。这可能是真实值为0，也可能是读取失败。\n");
    }
    printf("--- GG特定地址读取结束 ---\n\n");
    // --- GG直接地址读取测试结束 ---

    // --- 新增 读取第一个实体血量和坐标的测试代码 (基于 DrawPlayer.hpp 分析) ---
    printf("\n--- 开始读取特定游戏数据 (基于 DrawPlayer.hpp 分析的偏移) ---\n");

    // 确保我们有有效的基地址和PID才继续
    // (core_region_base在此之前已经被检查是否为0, target_process_handle 在程序开始时已检查)
    if (core_region_base != 0) {
        // 步骤 1: 从 libGameCore.so 基地址 + 0x2540 获取 temp1_val (实体相关的某个基础指针)
        // DrawPlayer.hpp 参考: long temp1 = ReadValue(libGame_base + 0x2540);
        uintptr_t temp1_addr = core_region_base + 0x2540;
        printf("中文注释: 计算 temp1_addr (core_region_base + 0x2540) = 0x%lx\n", temp1_addr);
        uintptr_t temp1_val = fetch_remote_pointer(target_process_handle, temp1_addr);

        if (temp1_val == 0) {
            fprintf(stderr, "中文注释: 错误 - 读取 temp1_val 失败 (地址: 0x%lx)\n", temp1_addr);
        } else {
            printf("中文注释: 成功 - 读取 temp1_val = 0x%lx\n", temp1_val);

            // 步骤 2: 从 temp1_val + 0x120 获取实体列表相关的指针 (entity_list_struct_addr)
            // DrawPlayer.hpp 参考: long bingxiang1 = temp1 + 0x120;
            uintptr_t entity_list_struct_addr = temp1_val + 0x120;
            printf("中文注释: 计算 entity_list_struct_addr (temp1_val + 0x120) = 0x%lx\n", entity_list_struct_addr);

            // 步骤 3: 获取第一个实体结构体的基址 (entity_base_addr)
            // DrawPlayer.hpp 逻辑: bingxiang6 = ReadValue(ReadValue(bingxiang1 + i * 0x18) + 0x68);
            // 我们取 i=0 (第一个实体)
            uintptr_t first_entity_ptr_location = entity_list_struct_addr; // For i=0, offset from bingxiang1 is +0
            printf("中文注释: 第一个实体在列表中的指针存储位置 (entity_list_struct_addr) = 0x%lx\n", first_entity_ptr_location);
            // Dereference 1: ReadValue(bingxiang1 + i*0x18)
            uintptr_t first_entity_ptr_value = fetch_remote_pointer(target_process_handle, first_entity_ptr_location);

            if (first_entity_ptr_value == 0) {
                fprintf(stderr, "中文注释: 错误 - 读取第一个实体的指针值失败 (指针存储地址: 0x%lx)\n", first_entity_ptr_location);
            } else {
                printf("中文注释: 成功 - 读取到第一个实体的指针值 first_entity_ptr_value = 0x%lx\n", first_entity_ptr_value);

                uintptr_t entity_base_addr_location = first_entity_ptr_value + 0x68; // (Value from previous step) + 0x68
                printf("中文注释: 计算实体基址的存储位置 (first_entity_ptr_value + 0x68) = 0x%lx\n", entity_base_addr_location);
                // Dereference 2: ReadValue( ... + 0x68)
                uintptr_t entity_base_addr = fetch_remote_pointer(target_process_handle, entity_base_addr_location);

                if (entity_base_addr == 0) {
                    fprintf(stderr, "中文注释: 错误 - 读取实体基址 entity_base_addr 失败 (指针存储地址: 0x%lx)\n", entity_base_addr_location);
                } else {
                    printf("中文注释: 成功 - 读取到实体基址 entity_base_addr = 0x%lx\n", entity_base_addr);

                    // 步骤 4: 读取实体血量
                    // DrawPlayer.hpp: Hp = driver->read<int>(ReadValue(bingxiang6 + 0x168) + 0x98);
                    uintptr_t health_struct_ptr_location = entity_base_addr + 0x168;
                    printf("中文注释: 计算健康结构体指针的存储位置 (entity_base_addr + 0x168) = 0x%lx\n", health_struct_ptr_location);
                    uintptr_t health_struct_ptr_value = fetch_remote_pointer(target_process_handle, health_struct_ptr_location);
                    if (health_struct_ptr_value == 0) {
                        fprintf(stderr, "中文注释: 错误 - 读取健康结构体指针值失败 (指针存储地址: 0x%lx)\n", health_struct_ptr_location);
                    } else {
                        printf("中文注释: 成功 - 读取到健康结构体指针值 health_struct_ptr_value = 0x%lx\n", health_struct_ptr_value);

                        uintptr_t current_hp_addr = health_struct_ptr_value + 0x98;
                        int current_hp = fetch_remote_integer(target_process_handle, current_hp_addr);

                        uintptr_t max_hp_addr = health_struct_ptr_value + 0xA0;
                        int max_hp = fetch_remote_integer(target_process_handle, max_hp_addr);

                        printf("中文注释: 信息 - 实体 0 - 当前血量: %d, 最大血量: %d (当前HP地址=0x%lx, 最大HP地址=0x%lx)\n", current_hp, max_hp, current_hp_addr, max_hp_addr);
                    }

                    // 步骤 5: 读取实体坐标 (简化版，假设非加密路径，并且coord_s3_ptr_addr_zuobiao_base直接包含最终坐标指针)
                    // DrawPlayer.hpp Path: bingxiang6 + 0x248 -> ptr1_val -> ptr1_val + 0x10 -> ptr2_val -> ptr2_val + 0x10 -> ptr3_addr (zuobiao_base)
                    // Then, if ReadDword(ptr3_addr)!=0, final_coord_ptr = ReadValue(ptr3_addr). Then +0x0 for X, +0x8 for Y/Z.
                    uintptr_t coord_s1_ptr_location = entity_base_addr + 0x248;
                    printf("中文注释: 计算坐标指针链S1的存储位置 (entity_base_addr + 0x248) = 0x%lx\n", coord_s1_ptr_location);
                    uintptr_t coord_s1_ptr_val = fetch_remote_pointer(target_process_handle, coord_s1_ptr_location);
                    if (coord_s1_ptr_val == 0) {
                        fprintf(stderr, "中文注释: 错误 - 读取坐标指针链 S1 值 (coord_s1_ptr_val) 失败 (指针存储地址: 0x%lx)\n", coord_s1_ptr_location);
                    } else {
                        printf("中文注释: 成功 - 读取 coord_s1_ptr_val = 0x%lx\n", coord_s1_ptr_val);
                        uintptr_t coord_s2_ptr_location = coord_s1_ptr_val + 0x10;
                        printf("中文注释: 计算坐标指针链S2的存储位置 (coord_s1_ptr_val + 0x10) = 0x%lx\n", coord_s2_ptr_location);
                        uintptr_t coord_s2_ptr_val = fetch_remote_pointer(target_process_handle, coord_s2_ptr_location);
                        if (coord_s2_ptr_val == 0) {
                            fprintf(stderr, "中文注释: 错误 - 读取坐标指针链 S2 值 (coord_s2_ptr_val) 失败 (指针存储地址: 0x%lx)\n", coord_s2_ptr_location);
                        } else {
                            printf("中文注释: 成功 - 读取 coord_s2_ptr_val = 0x%lx\n", coord_s2_ptr_val);
                            uintptr_t coord_s3_ptr_location_zuobiao_base = coord_s2_ptr_val + 0x10;
                            printf("中文注释: 计算坐标指针链S3(zuobiao_base)的存储位置 (coord_s2_ptr_val + 0x10) = 0x%lx\n", coord_s3_ptr_location_zuobiao_base);

                            // 简化: 直接读取最终坐标指针。实际 DrawPlayer.hpp 会先读一个值判断是否加密。
                            // 我们假设 coord_s3_ptr_location_zuobiao_base 这个地址里存的就是最终坐标结构体的指针 (final_coord_ptr)
                            uintptr_t final_coord_ptr = fetch_remote_pointer(target_process_handle, coord_s3_ptr_location_zuobiao_base);
                            printf("中文注释: _假设非加密路径_ 读取最终坐标指针 final_coord_ptr (从 coord_s3_ptr_location_zuobiao_base 读取) = 0x%lx\n", final_coord_ptr);

                            if (final_coord_ptr == 0) {
                                fprintf(stderr, "中文注释: 错误 - 读取最终坐标指针 final_coord_ptr 失败 (指针存储地址: 0x%lx). 可能实际路径需要解密或不同.\n", coord_s3_ptr_location_zuobiao_base);
                            } else {
                                printf("中文注释: 成功 - 读取到 final_coord_ptr = 0x%lx\n", final_coord_ptr);
                                uintptr_t x_addr = final_coord_ptr + 0x0;    // 最终坐标指针 + X偏移
                                int coord_x = fetch_remote_integer(target_process_handle, x_addr);

                                uintptr_t y_or_z_addr = final_coord_ptr + 0x8; // 最终坐标指针 + Y/Z偏移
                                int coord_y_or_z = fetch_remote_integer(target_process_handle, y_or_z_addr);

                                printf("中文注释: 信息 - 实体 0 - X坐标: %d, Y/Z坐标: %d (X地址=0x%lx, Y/Z地址=0x%lx)\n", coord_x, coord_y_or_z, x_addr, y_or_z_addr);
                            }
                        }
                    }
                }
            }
        }
    } else { // This else corresponds to the "if (core_region_base != 0)" check at the start of this new block
        fprintf(stderr, "中文注释: core_region_base (libGameCore.so 基址) 为0，跳过特定游戏数据读取测试。\n");
    }
    printf("--- 特定游戏数据读取测试结束 ---\n\n");
    // --- 新增测试代码结束 ---

    core_data_offset = core_region_base + 0x392A930;
    printf("计算数据偏移 core_data_offset: 0x%lx (基址 + 0x392A930)\n", core_data_offset);

    val1 = fetch_remote_pointer(target_process_handle, core_data_offset);
    if (val1 == 0 && core_data_offset != 0) {
        fprintf(stderr, "警告: val1 读取失败或为0 (偏移: 0x%lx)。后续读取可能无效。\n", core_data_offset);
    } else {
        printf("读取 val1 (从 0x%lx): 0x%lx\n", core_data_offset, val1);
    }

    val2 = fetch_remote_pointer(target_process_handle, val1 + 0x120 + (uintptr_t)i * 0x18);
    if (val2 == 0 && (val1 + 0x120 + (uintptr_t)i * 0x18) != 0) {
        fprintf(stderr, "警告: val2 读取失败或为0 (偏移: 0x%lx)。后续读取可能无效。\n", val1 + 0x120 + (uintptr_t)i * 0x18);
    } else {
        printf("读取 val2 (从 0x%lx + 0x120 + %d*0x18 = 0x%lx): 0x%lx\n",
               val1, i, val1 + 0x120 + (uintptr_t)i * 0x18, val2);
    }

    entity_list_ptr = fetch_remote_pointer(target_process_handle, val2 + 0x68);
     if (entity_list_ptr == 0 && (val2 + 0x68) != 0) {
        fprintf(stderr, "警告: entity_list_ptr 读取失败或为0 (偏移: 0x%lx)。后续读取可能无效。\n", val2 + 0x68);
    } else {
        printf("读取 entity_list_ptr (从 0x%lx + 0x68 = 0x%lx): 0x%lx\n", val2, val2 + 0x68, entity_list_ptr);
    }

    entity_id = fetch_remote_integer(target_process_handle, entity_list_ptr + 0x28);
    printf("读取 entity_id (从 0x%lx + 0x28 = 0x%lx): %d (0x%x)\n", entity_list_ptr, entity_list_ptr + 0x28, entity_id, entity_id);

    entity_prop_base = fetch_remote_pointer(target_process_handle, entity_list_ptr + 0x128);
    if (entity_prop_base == 0 && (entity_list_ptr + 0x128) != 0) {
        fprintf(stderr, "警告: entity_prop_base 读取失败或为0 (偏移: 0x%lx)。后续读取可能无效。\n", entity_list_ptr + 0x128);
    } else {
        printf("读取 entity_prop_base (从 0x%lx + 0x128 = 0x%lx): 0x%lx\n", entity_list_ptr, entity_list_ptr + 0x128, entity_prop_base);
    }

    entity_health = fetch_remote_integer(target_process_handle, entity_prop_base + 0xA0);
    printf("读取 entity_health (从 0x%lx + 0xA0 = 0x%lx): %d (0x%x)\n", entity_prop_base, entity_prop_base + 0xA0, entity_health, entity_health);

    printf("\n--- 最终结果 ---\n");
    printf("实体 ID (Entity ID): %d\n", entity_id);
    printf("当前健康值 (Current Health): %d\n", entity_health);

    // 3. 关闭 IPC 通道
    if (g_ipc_descriptor >= 0) {
        close(g_ipc_descriptor);
        printf("\nIPC 通道已关闭。\n");
    }

    return EXIT_SUCCESS;
}
