#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/sched.h>      // 用于 task_struct
#include <linux/sched/signal.h> // get_task_mm, pid_task
#include <linux/sched/mm.h>   // get_task_mm (newer kernels)
#include <linux/mm.h>         // 用于 mm_struct, vm_area_struct, find_vma, access_process_vm
// #include <linux/highmem.h> // 不再需要，因为移除了 kmap/kunmap
#include <linux/pid.h>        // 用于 find_get_pid, put_pid
#include <linux/fs.h>         // 用于 VMA 迭代 (虽然 mm_struct.mmap 应该足够)
#include <linux/path.h>       // 用于 d_path
#include <linux/err.h>        // 用于 IS_ERR, PTR_ERR
#include <net/sock.h>       // 用于 Netlink
#include <linux/string.h>     // 用于 strcmp, strncpy, strrchr
#include <linux/kthread.h>    // 用于 kthread 函数
#include <linux/list.h>       // 用于 struct list_head
#include <linux/spinlock.h>   // 用于 spinlock_t
#include <linux/slab.h>       // 用于 kmalloc, kfree
#include <linux/sched/signal.h> // signal_pending 等 (kthread_stop 处理大部分)
// #include <linux/cpumask.h> // 用于 CPU 亲和性设置 (可选)

// --- XOR Obfuscation ---
// Obfuscated name for g_data_transform_key
static const unsigned char g_secret_seq_const[] = {0x5A, 0xA5, 0x3C, 0xC3, 0xF0, 0x0F, 0xAA, 0x55};

// Shared secret for authentication (obfuscated name: g_channel_auth_sequence)
static const unsigned char g_channel_auth_sequence[] = { // __maybe_unused removed
    0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81,
    0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09
};

// Obfuscated name for transform_data_buffer
static void transform_data_buffer(unsigned char *buffer_addr, size_t buffer_len) {
    size_t key_len = sizeof(g_secret_seq_const);
    size_t i;
    for (i = 0; i < buffer_len; ++i) {
        buffer_addr[i] = buffer_addr[i] ^ g_secret_seq_const[i % key_len];
    }
}
// --- End XOR Obfuscation ---

// 模块许可证声明
MODULE_LICENSE("GPL");
// 模块作者声明
MODULE_AUTHOR("Obfuscated Author");
// 模块描述
MODULE_DESCRIPTION("通过特定通道进行远程数据查询的内核组件。");

// 定义特定通道ID (例如 CTL_CHANNEL_ID 29) - 值已更改
#define CTL_CHANNEL_ID 29 // 原 NETLINK_MY_PROTOCOL, 值从31更改为29
// 定义请求类型
#define REQ_TYPE_QUERY_BASE 1 // 获取区域基地址请求 (原 MSG_TYPE_GET_MODULE_BASE)
#define REQ_TYPE_FETCH_PTR 2    // 读取指针大小数据请求 (原 MSG_TYPE_READ_UINTPTR)
#define REQ_TYPE_FETCH_INT 3        // 读取整型数据请求 (原 MSG_TYPE_READ_INT)
#define RESP_TYPE_ERROR_STATUS 4           // 错误消息类型 (原 MSG_TYPE_ERROR)

// 上行消息结构体 (用户空间到内核空间)
typedef struct {
    int type;             // 消息类型 (REQ_TYPE_QUERY_BASE 等)
    pid_t target_id;      // 目标进程ID (原 pid)
    unsigned long data_offset; // 读取操作的目标地址 (原 address)
    char object_label[128]; // 区域标签 (用于获取模块基地址, 原 name)
    unsigned char auth_key_data[16]; // New field for the token (size matches secret)
} ipc_msg_upstream_t; // 原 nl_request_t

// 下行消息结构体 (内核空间到用户空间)
typedef struct {
    int type;             // 响应类型 (对应请求类型或错误类型)
    unsigned long value;  // 读取结果或基地址
    int error_code;       // 错误码 (0 表示成功)
} ipc_msg_downstream_t; // 原 nl_response_t

// --- Kthread 工作队列相关定义 ---
typedef struct {
    struct list_head list_node;      // 队列中的链接节点
    ipc_msg_upstream_t received_data; // 从用户空间接收的实际请求数据
    pid_t client_pid;                // 发送请求的用户空间客户端PID
    uint32_t nl_seq;                 // Netlink 消息序列号，用于响应
} queued_action_item_t; // 原 pending_operation_t

static LIST_HEAD(g_work_item_queue); // 工作项队列头
static DEFINE_SPINLOCK(g_queue_lock);  // 保护队列的自旋锁
static DECLARE_WAIT_QUEUE_HEAD(g_kthread_wait_queue); // Kthread 等待队列
static struct task_struct *g_processing_thread = NULL; // Kthread 任务结构体

// IPC 通道套接字全局变量
static struct sock *g_ipc_socket = NULL; // 原 nl_sk

// Kthread 主函数声明
static int bg_task_loop(void *data); // 原 processing_thread_main

// 函数前向声明 (其他函数)
static void ipc_channel_receiver(struct sk_buff *skb); // 原 nl_recv_msg
static unsigned long find_target_region_start(pid_t target_id, const char* object_label); // 原 get_module_base_address
static int acquire_remote_data_segment(pid_t target_id, unsigned long data_offset, void *out_buffer, size_t size); // 原 read_memory_common
static int retrieve_offset_value(pid_t target_id, unsigned long data_offset, unsigned long *val_ptr); // 原 read_pointer_from_address
static int retrieve_integer_value(pid_t target_id, unsigned long data_offset, int *val_ptr); // 原 read_int_from_address


/**
 * @brief 获取指定目标ID进程中名为object_label的区域的起始地址
 *
 * @param target_id 目标进程的PID (原 pid)
 * @param object_label 要查找的区域标签 (原 module_name)
 * @return unsigned long 区域的起始地址，如果未找到或发生错误则返回0
 */
static unsigned long find_target_region_start(pid_t target_id, const char* object_label) {
    struct task_struct *target_process_info;    // 原 task
    struct mm_struct *process_mem_context;      // 原 mm
    struct vm_area_struct *mem_region_descriptor; // 原 vma // Note: This function still uses VMA iteration. access_process_vm is for acquire_remote_data_segment.
    unsigned long base_address = 0;
    char *path_buf = NULL;
    const int path_buf_len = 256; // 路径缓冲区的长度

    printk(KERN_INFO "find_target_region_start: TargetID=%d, ObjectLabel=%s\n", target_id, object_label);

    // 为路径缓冲区分配内存
    path_buf = kmalloc(path_buf_len, GFP_KERNEL);
    if (!path_buf) {
        printk(KERN_ERR "find_target_region_start: Failed to allocate path_buf\n");
        return 0;
    }

    // 查找 task_struct
    rcu_read_lock(); // RCU锁保护task查找
    target_process_info = pid_task(find_get_pid(target_id), PIDTYPE_PID);
    if (target_process_info) {
        get_task_struct(target_process_info); // 增加task_struct的引用计数
    }
    rcu_read_unlock();

    if (!target_process_info) {
        printk(KERN_WARNING "find_target_region_start: Process info for TargetID %d not found.\n", target_id);
        kfree(path_buf);
        return 0;
    }

    // 获取 mm_struct
    process_mem_context = get_task_mm(target_process_info);
    put_task_struct(target_process_info); // 释放task_struct的引用

    if (!process_mem_context) {
        printk(KERN_WARNING "find_target_region_start: Could not get memory context for TargetID %d.\n", target_id);
        kfree(path_buf);
        return 0;
    }

    // 锁定并遍历VMA
    if (mmap_read_lock_killable(process_mem_context)) { // 请求读锁，允许被信号中断
        printk(KERN_WARNING "find_target_region_start: Failed to acquire mmap_read_lock for TargetID %d\n", target_id);
        mmput(process_mem_context); // mm_struct引用计数减1
        kfree(path_buf);
        return 0;
    }

    for (mem_region_descriptor = process_mem_context->mmap; mem_region_descriptor; mem_region_descriptor = mem_region_descriptor->vm_next) {
        if (mem_region_descriptor->vm_file) {
            char *actual_path;
            char *basename;

            memset(path_buf, 0, path_buf_len);
            actual_path = d_path(&mem_region_descriptor->vm_file->f_path, path_buf, path_buf_len);

            if (IS_ERR(actual_path)) {
                // printk(KERN_WARNING "find_target_region_start: Error getting path for mem_region_descriptor, error %ld\n", PTR_ERR(actual_path));
                continue; // 路径获取错误，跳过此VMA
            }

            // 获取文件名 (basename)
            basename = strrchr(actual_path, '/');
            if (basename) {
                basename++; // 跳过 '/'
            } else {
                basename = actual_path; // 如果没有 '/', 则整个路径是文件名
            }

            // printk(KERN_DEBUG "find_target_region_start: Checking VMA: %s (0x%lx-0x%lx)\n", basename, mem_region_descriptor->vm_start, mem_region_descriptor->vm_end);

            if (strcmp(basename, object_label) == 0) {
                base_address = mem_region_descriptor->vm_start;
                printk(KERN_INFO "find_target_region_start: Found object %s at 0x%lx for TargetID %d\n", object_label, base_address, target_id);
                break; // 找到模块，跳出循环
            }
        }
    }

    mmap_read_unlock(process_mem_context); // 释放读锁
    mmput(process_mem_context);            // mm_struct引用计数减1
    kfree(path_buf);      // 释放路径缓冲区

    return base_address;
}

/**
 * @brief 从目标进程的指定地址读取内存数据段
 *
 * @param target_id 目标进程ID (原 pid)
 * @param data_offset 要读取的内存地址 (原 address)
 * @param out_buffer 用于存储读取数据的缓冲区
 * @param size 要读取的数据大小 (字节)
 * @return int 0 表示成功, 负值表示错误码
 */
static int acquire_remote_data_segment(pid_t target_id, unsigned long data_offset, void *out_buffer, size_t size) {
    struct task_struct *target_process_info = NULL;
    struct pid *pid_struct = NULL;
    int ret_val = 0;

    pid_struct = find_get_pid(target_id);
    if (!pid_struct) {
        printk(KERN_WARNING "acquire_remote_data_segment: PID struct for TargetID %d not found.\n", target_id);
        return -ESRCH;
    }

    rcu_read_lock();
    target_process_info = pid_task(pid_struct, PIDTYPE_PID);
    if (target_process_info) {
        get_task_struct(target_process_info); // Increment task reference count
    }
    rcu_read_unlock();

    if (!target_process_info) {
        printk(KERN_WARNING "acquire_remote_data_segment: Task for TargetID %d not found.\n", target_id);
        put_pid(pid_struct);
        return -ESRCH;
    }

    // It's good practice to check if the target process has an mm_struct,
    // as access_process_vm will operate on it.
    if (!target_process_info->mm) {
        printk(KERN_WARNING "acquire_remote_data_segment: Target process (ID: %d) has no mm_struct (e.g., kernel thread).\n", target_id);
        put_task_struct(target_process_info);
        put_pid(pid_struct);
        return -EINVAL;
    }

    ret_val = access_process_vm(target_process_info, data_offset, out_buffer, size, 0); // 0 for flags (read)

    if (ret_val == size) {
        // printk(KERN_INFO "acquire_remote_data_segment: Successfully read %d bytes from TargetID %d at 0x%lx via access_process_vm.\n", ret_val, target_id, data_offset);
        ret_val = 0; // Success
    } else if (ret_val >= 0 && ret_val < size) {
        printk(KERN_WARNING "acquire_remote_data_segment: Partial read (%d of %zu bytes) from TargetID %d at 0x%lx via access_process_vm.\n", ret_val, size, target_id, data_offset);
        ret_val = -EFAULT; // Partial read is an error for this use-case
    } else { // ret_val is negative
        printk(KERN_WARNING "acquire_remote_data_segment: access_process_vm failed for TargetID %d at 0x%lx. Error: %d\n", target_id, data_offset, ret_val);
        // ret_val already holds the negative error code
    }

    put_task_struct(target_process_info); // Decrement task reference count
    put_pid(pid_struct);

    return ret_val;
}


/**
 * @brief 从目标进程的指定地址读取一个指针大小的数据 (unsigned long)
 *
 * @param target_id 目标进程ID (原 pid)
 * @param data_offset 要读取的内存地址 (原 address)
 * @param val_ptr 指向用于存储读取值的 unsigned long 指针
 * @return int 0 表示成功, 负值表示错误码
 */
static int retrieve_offset_value(pid_t target_id, unsigned long data_offset, unsigned long *val_ptr) {
    // printk(KERN_INFO "retrieve_offset_value called for TargetID: %d, DataOffset: 0x%lx\n", target_id, data_offset);
    return acquire_remote_data_segment(target_id, data_offset, val_ptr, sizeof(unsigned long));
}

/**
 * @brief 从目标进程的指定地址读取一个整型数据 (int)
 *
 * @param target_id 目标进程ID (原 pid)
 * @param data_offset 要读取的内存地址 (原 address)
 * @param val_ptr 指向用于存储读取值的 int 指针
 * @return int 0 表示成功, 负值表示错误码
 */
static int retrieve_integer_value(pid_t target_id, unsigned long data_offset, int *val_ptr) {
    // printk(KERN_INFO "retrieve_integer_value called for TargetID: %d, DataOffset: 0x%lx\n", target_id, data_offset);
    return acquire_remote_data_segment(target_id, data_offset, val_ptr, sizeof(int));
}

/**
 * @brief 将数据段写入目标进程的指定地址
 *
 * @param target_id 目标进程ID
 * @param data_offset 要写入的内存地址
 * @param data_to_write 指向要写入数据的缓冲区
 * @param size 要写入的数据大小 (字节)
 * @return int 0 表示成功, 负值表示错误码
 */
static int write_remote_data_segment(pid_t target_id, unsigned long data_offset, void *data_to_write, size_t size) {
    struct task_struct *target_process_info = NULL;
    struct pid *pid_struct = NULL;
    int ret_val = 0;

    pid_struct = find_get_pid(target_id);
    if (!pid_struct) {
        printk(KERN_WARNING "write_remote_data_segment: PID struct for TargetID %d not found.\n", target_id);
        return -ESRCH;
    }

    rcu_read_lock();
    target_process_info = pid_task(pid_struct, PIDTYPE_PID);
    if (target_process_info) {
        get_task_struct(target_process_info);
    }
    rcu_read_unlock();

    if (!target_process_info) {
        printk(KERN_WARNING "write_remote_data_segment: Task for TargetID %d not found.\n", target_id);
        put_pid(pid_struct);
        return -ESRCH;
    }

    if (!target_process_info->mm) {
        printk(KERN_WARNING "write_remote_data_segment: Target process (ID: %d) has no mm_struct.\n", target_id);
        put_task_struct(target_process_info);
        put_pid(pid_struct);
        return -EINVAL;
    }

    // The '1' in the last argument of access_process_vm means 'write' (vs '0' for read)
    ret_val = access_process_vm(target_process_info, data_offset, data_to_write, size, 1);

    put_task_struct(target_process_info);
    put_pid(pid_struct);

    if (ret_val == size) {
        // printk(KERN_INFO "write_remote_data_segment: Successfully wrote %ld bytes to TargetID %d at 0x%lx.\n", (long)ret_val, target_id, data_offset);
        return 0; // Success
    } else if (ret_val >= 0 && ret_val < size) {
        printk(KERN_WARNING "write_remote_data_segment: Partial write (%d of %zu bytes) to TargetID %d at 0x%lx.\n", ret_val, size, target_id, data_offset);
        return -EFAULT;
    } else {
        printk(KERN_WARNING "write_remote_data_segment: access_process_vm write failed for TargetID %d at 0x%lx. Error: %d\n", target_id, data_offset, ret_val);
        return ret_val;
    }
}

static int write_integer_to_address(pid_t target_id, unsigned long data_offset, int value_to_write) {
    // printk(KERN_INFO "write_integer_to_address: TargetID: %d, Offset: 0x%lx, Value: %d\n", target_id, data_offset, value_to_write);
    return write_remote_data_segment(target_id, data_offset, &value_to_write, sizeof(int));
}

static int write_pointer_to_address(pid_t target_id, unsigned long data_offset, unsigned long value_to_write) {
    // printk(KERN_INFO "write_pointer_to_address: TargetID: %d, Offset: 0x%lx, Value: 0x%lx\n", target_id, data_offset, value_to_write);
    return write_remote_data_segment(target_id, data_offset, &value_to_write, sizeof(unsigned long));
}

/**
 * @brief IPC通道消息接收回调函数 (原 Netlink消息接收回调函数)
 *
 * @param skb 套接字缓冲区，包含接收到的IPC消息
 */
static void ipc_channel_receiver(struct sk_buff *skb) { // 原 nl_recv_msg
    struct nlmsghdr *nlh;
    ipc_msg_upstream_t *up_payload_from_nl;
    queued_action_item_t *new_op;
    pid_t user_pid;

    nlh = (struct nlmsghdr *)skb->data;
    if (nlh->nlmsg_len < nlmsg_msg_size(sizeof(ipc_msg_upstream_t))) {
        printk(KERN_ERR "ipc_channel_receiver: IPC message payload too short.\n");
        return;
    }

    up_payload_from_nl = (ipc_msg_upstream_t *)NLMSG_DATA(nlh);
    user_pid = nlh->nlmsg_pid;

    new_op = kmalloc(sizeof(queued_action_item_t), GFP_ATOMIC); // 使用GFP_ATOMIC，因为在软中断上下文中
    if (!new_op) {
        printk(KERN_ERR "ipc_channel_receiver: Failed to allocate memory for new operation item.\n");
        // 可以考虑发送一个错误回复给用户，但这会使回调复杂化
        return;
    }

    // Copy encrypted data first
    memcpy(&new_op->received_data, up_payload_from_nl, sizeof(ipc_msg_upstream_t));

    // Then, decrypt the copy
    transform_data_buffer((unsigned char *)&new_op->received_data, sizeof(ipc_msg_upstream_t)); // XOR obfuscation re-enabled

    // Add token validation here:
    if (memcmp(new_op->received_data.auth_key_data, g_channel_auth_sequence, sizeof(g_channel_auth_sequence)) != 0) {
        printk(KERN_WARNING "ipc_channel_receiver: Invalid access token from PID %d. Discarding request.\n", user_pid);
        kfree(new_op);
        return; // Do not queue if token is invalid
    }

    // Token is valid, proceed with logging and queuing
    new_op->client_pid = user_pid;
    new_op->nl_seq = nlh->nlmsg_seq; // 保存序列号

    // Log after decryption and token validation
    printk(KERN_INFO "ipc_channel_receiver: Queuing validated & decrypted request type %d from PID %d (TargetID: %d)\n",
           new_op->received_data.type, new_op->client_pid, new_op->received_data.target_id);
    INIT_LIST_HEAD(&new_op->list_node);

    spin_lock_bh(&g_queue_lock);
    list_add_tail(&new_op->list_node, &g_work_item_queue);
    spin_unlock_bh(&g_queue_lock);

    wake_up_interruptible(&g_kthread_wait_queue); // 唤醒内核线程处理队列
}


// --- Kthread 工作函数 ---
static int bg_task_loop(void *data) {
    queued_action_item_t *current_op = NULL;
    ipc_msg_downstream_t down_payload; // 响应消息体
    struct sk_buff *skb_out;          // 用于发送响应的skb
    struct nlmsghdr *nlh_resp;        // 响应的Netlink消息头
    int msg_size;
    int res;

    printk(KERN_INFO "bg_task_loop: Kthread started.\n");

    while (!kthread_should_stop()) {
        current_op = NULL;

        spin_lock_bh(&g_queue_lock);
        if (!list_empty(&g_work_item_queue)) {
            current_op = list_first_entry(&g_work_item_queue, queued_action_item_t, list_node);
            list_del(&current_op->list_node); // 从队列中移除
        }
        spin_unlock_bh(&g_queue_lock);

        if (current_op) {
            printk(KERN_INFO "bg_task_loop: Processing request type %d for TargetID %d from client PID %d.\n",
                   current_op->received_data.type, current_op->received_data.target_id, current_op->client_pid);

            memset(&down_payload, 0, sizeof(ipc_msg_downstream_t));
            down_payload.type = current_op->received_data.type;

            switch (current_op->received_data.type) {
                case REQ_TYPE_QUERY_BASE:
                    down_payload.value = find_target_region_start(current_op->received_data.target_id, current_op->received_data.object_label);
                    if (down_payload.value == 0) {
                        down_payload.error_code = -ENOENT;
                    } else {
                        down_payload.error_code = 0;
                    }
                    break;
                case REQ_TYPE_FETCH_PTR: {
                    unsigned long temp_ul_val;
                    down_payload.error_code = retrieve_offset_value(current_op->received_data.target_id, current_op->received_data.data_offset, &temp_ul_val);
                    if (down_payload.error_code == 0) {
                        down_payload.value = temp_ul_val;
                    } else {
                        down_payload.value = 0;
                    }
                    break;
                }
                case REQ_TYPE_FETCH_INT: {
                    int temp_int_val;
                    down_payload.error_code = retrieve_integer_value(current_op->received_data.target_id, current_op->received_data.data_offset, &temp_int_val);
                    if (down_payload.error_code == 0) {
                        down_payload.value = (unsigned long)temp_int_val;
                    } else {
                        down_payload.value = 0;
                    }
                    break;
                }
                // ADD THESE NEW CASES:
                case REQ_TYPE_WRITE_INT: {
                    down_payload.error_code = write_integer_to_address(current_op->received_data.target_id,
                                                                     current_op->received_data.data_offset,
                                                                     (int)current_op->received_data.value_to_write);
                    down_payload.value = 0;
                    break;
                }
                case REQ_TYPE_WRITE_PTR: {
                    down_payload.error_code = write_pointer_to_address(current_op->received_data.target_id,
                                                                       current_op->received_data.data_offset,
                                                                       current_op->received_data.value_to_write);
                    down_payload.value = 0;
                    break;
                }
                default:
                    down_payload.type = RESP_TYPE_ERROR_STATUS;
                    down_payload.error_code = -EINVAL;
            }

            msg_size = sizeof(ipc_msg_downstream_t);
            skb_out = nlmsg_new(msg_size, GFP_KERNEL); // 在kthread中可以用GFP_KERNEL
            if (!skb_out) {
                printk(KERN_ERR "bg_task_loop: Failed to allocate skb for response.\n");
                kfree(current_op); // 释放操作项
                continue; // 继续下一个循环迭代
            }

            nlh_resp = nlmsg_put(skb_out, 0, current_op->nl_seq, NLMSG_DONE, msg_size, 0);

            // Encrypt/Obfuscate outgoing payload before copying to SKB
            transform_data_buffer((unsigned char *)&down_payload, sizeof(ipc_msg_downstream_t)); // XOR obfuscation re-enabled

            memcpy(NLMSG_DATA(nlh_resp), &down_payload, msg_size);

            res = nlmsg_unicast(g_ipc_socket, skb_out, current_op->client_pid);
            if (res < 0) {
                printk(KERN_ERR "bg_task_loop: Error sending IPC message to PID %d: %d\n", current_op->client_pid, res);
                // nlmsg_unicast 会在失败时释放 skb_out
            } else {
                printk(KERN_INFO "bg_task_loop: Sent IPC response to PID %d.\n", current_op->client_pid);
            }
            kfree(current_op); // 释放已处理的操作项
        } else {
            // 队列为空，等待新的工作项或停止信号
            wait_event_interruptible(g_kthread_wait_queue,
                                     !list_empty(&g_work_item_queue) || kthread_should_stop());
        }
    }
    printk(KERN_INFO "bg_task_loop: Kthread stopping.\n");
    return 0;
}


// IPC 通道内核配置结构体
static struct netlink_kernel_cfg g_ipc_channel_config = {
    .input = ipc_channel_receiver, // 设置IPC消息处理函数
};

/**
 * @brief 核心组件初始化函数 (原 模块初始化函数)
 *
 * @return int 0 表示成功, 负值表示错误
 */
static int __init core_component_initialize(void) { // 原 my_module_init
    printk(KERN_INFO "核心数据查询组件加载成功。\n");

    g_ipc_socket = netlink_kernel_create(&init_net, CTL_CHANNEL_ID, &g_ipc_channel_config);
    if (!g_ipc_socket) {
        printk(KERN_ALERT "创建IPC通讯通道失败。\n");
        return -ENOMEM;
    }
    printk(KERN_INFO "IPC通讯通道创建成功。\n");

    // 启动内核线程
    g_processing_thread = kthread_run(bg_task_loop, NULL, "dpkth"); // 使用混淆的线程名
    if (IS_ERR(g_processing_thread)) {
        printk(KERN_ALERT "创建处理线程失败: %ld\n", PTR_ERR(g_processing_thread));
        netlink_kernel_release(g_ipc_socket);
        g_ipc_socket = NULL;
        return PTR_ERR(g_processing_thread);
    }
    printk(KERN_INFO "数据处理后台任务已启动。\n"); // Obfuscated message

    /* // CPU 亲和性设置示例 (可选)
    // #include <linux/cpumask.h>
    // struct cpumask mask;
    // cpumask_clear(&mask);
    // cpumask_set_cpu(0, &mask); // 示例：绑定到CPU 0
    // if (g_processing_thread) {
    //    int ret_affinity = set_cpus_allowed_ptr(g_processing_thread, &mask);
    //    if (ret_affinity < 0) {
    //        printk(KERN_WARNING "未能将处理线程绑定到指定CPU: %d\n", ret_affinity);
    //    } else {
    //        printk(KERN_INFO "处理线程已绑定到指定CPU。\n");
    //    }
    // }
    */

    return 0;
}

/**
 * @brief 核心组件退出函数 (原 模块退出函数)
 */
static void __exit core_component_terminate(void) { // 原 my_module_exit
    queued_action_item_t *current_op, *tmp;

    // 停止内核线程
    if (g_processing_thread) {
        printk(KERN_INFO "正在停止数据处理后台任务...\n"); // Obfuscated message
        kthread_stop(g_processing_thread);
        g_processing_thread = NULL;
        printk(KERN_INFO "数据处理后台任务已停止。\n"); // Obfuscated message
    }

    // 释放Netlink套接字
    if (g_ipc_socket) {
        netlink_kernel_release(g_ipc_socket);
        g_ipc_socket = NULL;
        printk(KERN_INFO "IPC通讯通道已释放。\n");
    }

    // 清理工作队列中剩余的项目
    printk(KERN_INFO "清理剩余的挂起操作...\n");
    spin_lock_bh(&g_queue_lock);
    list_for_each_entry_safe(current_op, tmp, &g_work_item_queue, list_node) {
        list_del(&current_op->list_node);
        kfree(current_op);
        printk(KERN_INFO "已释放一个挂起的队列项目。\n");
    }
    spin_unlock_bh(&g_queue_lock);
    printk(KERN_INFO "所有挂起的操作已清理。\n");

    printk(KERN_INFO "核心数据查询组件已卸载。\n");
}

// 注册组件初始化和退出函数
module_init(core_component_initialize);
module_exit(core_component_terminate);
