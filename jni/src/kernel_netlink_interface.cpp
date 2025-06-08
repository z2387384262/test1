#include "kernel_netlink_interface.h"

// Definition for the global IPC descriptor
int g_netlink_ipc_descriptor = -1;

/**
 * @brief Initializes the Netlink socket for communication with the kernel module.
 * @return int 0 on success, -1 on failure.
 */
int initialize_netlink_connection() {
    struct sockaddr_nl src_addr;

    g_netlink_ipc_descriptor = socket(PF_NETLINK, SOCK_RAW, NETLINK_CTL_CHANNEL_ID);
    if (g_netlink_ipc_descriptor < 0) {
        perror("kernel_netlink_interface: ERROR creating Netlink socket");
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); // Use current process PID
    src_addr.nl_groups = 0; // Not using multicast groups

    if (bind(g_netlink_ipc_descriptor, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
        perror("kernel_netlink_interface: ERROR binding Netlink socket");
        close(g_netlink_ipc_descriptor);
        g_netlink_ipc_descriptor = -1;
        return -1;
    }

    fprintf(stderr, "kernel_netlink_interface: Netlink IPC channel initialized successfully (fd: %d, pid: %d).\n", g_netlink_ipc_descriptor, getpid());
    return 0;
}

/**
 * @brief Closes the Netlink socket.
 */
void close_netlink_connection() {
    if (g_netlink_ipc_descriptor >= 0) {
        close(g_netlink_ipc_descriptor);
        g_netlink_ipc_descriptor = -1;
        fprintf(stderr, "kernel_netlink_interface: Netlink IPC channel closed.\n");
    }
}

/**
 * @brief Execute IPC transaction (send request and receive response).
 *
 * @param up_payload Pointer to netlink_ipc_msg_upstream_t structure containing request data.
 * @param down_payload Pointer to netlink_ipc_msg_downstream_t structure to store kernel's response.
 * @return int 0 on success, -1 on local error, or kernel's error code.
 */
int execute_netlink_ipc_transaction(netlink_ipc_msg_upstream_t *up_payload, netlink_ipc_msg_downstream_t *down_payload) {
    if (g_netlink_ipc_descriptor < 0) {
        fprintf(stderr, "kernel_netlink_interface: Netlink IPC descriptor not initialized.\n");
        return -1;
    }

    struct sockaddr_nl dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    ssize_t recv_len;

    // Prepare Netlink message header for upstream
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(netlink_ipc_msg_upstream_t)));
    if (!nlh) {
        perror("kernel_netlink_interface: ERROR allocating Netlink message header");
        return -1;
    }
    memset(nlh, 0, NLMSG_SPACE(sizeof(netlink_ipc_msg_upstream_t)));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(netlink_ipc_msg_upstream_t));
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;

    // Create a copy of the upstream payload for transformation, to keep original for logging if needed
    netlink_ipc_msg_upstream_t transformed_up_payload;
    memcpy(&transformed_up_payload, up_payload, sizeof(netlink_ipc_msg_upstream_t));
    netlink_transform_data_buffer((unsigned char *)&transformed_up_payload, sizeof(netlink_ipc_msg_upstream_t));
    memcpy(NLMSG_DATA(nlh), &transformed_up_payload, sizeof(netlink_ipc_msg_upstream_t));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(g_netlink_ipc_descriptor, &msg, 0) < 0) {
        perror("kernel_netlink_interface: ERROR sendmsg failed");
        fprintf(stderr, "kernel_netlink_interface: Failed request (send): type=%d, target_id=%d, offset=0x%lx\n",
                 up_payload->type, up_payload->target_id, up_payload->data_offset);
        free(nlh);
        return -1;
    }

    // Clear the nlh for receiving. It's good practice to re-initialize or clear.
    // The existing allocated buffer is large enough for the downstream message as well,
    // assuming netlink_ipc_msg_downstream_t is not larger than netlink_ipc_msg_upstream_t.
    // For robustness, one might reallocate or use a buffer sized for the larger of the two.
    // However, NLMSG_SPACE is based on payload size, so we should be fine if we expect
    // a netlink_ipc_msg_downstream_t. Let's adjust the iov_len for clarity for receive.
    // We expect to receive a netlink_ipc_msg_downstream_t.
    memset(nlh, 0, NLMSG_SPACE(sizeof(netlink_ipc_msg_upstream_t))); // Zero out the buffer before recv
    iov.iov_base = (void *)nlh;
    // Prepare to receive a message of type netlink_ipc_msg_downstream_t
    // The buffer nlh was allocated with NLMSG_SPACE(sizeof(netlink_ipc_msg_upstream_t)).
    // Ensure this buffer is large enough for NLMSG_SPACE(sizeof(netlink_ipc_msg_downstream_t)).
    // For this implementation, let's assume upstream payload size is >= downstream payload size.
    // If not, this could be a source of buffer overflow when reading the response.
    // A safer approach would be to use a buffer sized for the maximum expected payload:
    // max_payload_size = max(sizeof(netlink_ipc_msg_upstream_t), sizeof(netlink_ipc_msg_downstream_t))
    // nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(max_payload_size));
    iov.iov_len = NLMSG_SPACE(sizeof(netlink_ipc_msg_downstream_t)); // Corrected: use downstream size for recv


    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    recv_len = recvmsg(g_netlink_ipc_descriptor, &msg, 0);
    if (recv_len < 0) {
        perror("kernel_netlink_interface: ERROR recvmsg failed");
        fprintf(stderr, "kernel_netlink_interface: Failed request (recv): type=%d, target_id=%d, offset=0x%lx\n",
                 up_payload->type, up_payload->target_id, up_payload->data_offset);
        free(nlh);
        return -1;
    }

    if (recv_len < (ssize_t)sizeof(struct nlmsghdr)) {
        fprintf(stderr, "kernel_netlink_interface: Received message too short. recv_len=%zd\n", recv_len);
        free(nlh);
        return -1;
    }

    // Check if the received message is an error message from Netlink subsystem
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        if (recv_len < (ssize_t)NLMSG_HDRLEN + (ssize_t)sizeof(struct nlmsgerr)) {
            fprintf(stderr, "kernel_netlink_interface: Received NLMSG_ERROR too short. recv_len=%zd\n", recv_len);
            free(nlh);
            return -1;
        }
        struct nlmsgerr *nlerr = (struct nlmsgerr*)NLMSG_DATA(nlh);
        // nlerr->error contains the negative errno value for the error
        // A value of 0 in nlerr->error means an ACK, not an error.
        if (nlerr->error != 0) {
            fprintf(stderr, "kernel_netlink_interface: Netlink error: %s (%d) for request: type=%d, target_id=%d, offset=0x%lx\n",
                    strerror(-nlerr->error), -nlerr->error,
                    up_payload->type, up_payload->target_id, up_payload->data_offset);
            free(nlh);
            return nlerr->error; // Return the negative errno
        }
        // If nlerr->error is 0, it's an ACK. We expect a data message, not just an ACK.
        // This path might indicate an issue if we were expecting data.
        // However, for some netlink protocols, an ACK might be a valid response.
        // Given our protocol, we expect a data payload (netlink_ipc_msg_downstream_t).
        // If we receive an ACK here, it means the kernel didn't send our custom data structure back.
        // This could happen if the kernel module sent an ACK and closed the transaction,
        // or if there's a misunderstanding of the protocol.
        // For now, we'll assume data is expected. If only an ACK is received and no data,
        // NLMSG_OK might fail or NLMSG_DATA might point to unexpected memory.
    }


    if (!NLMSG_OK(nlh, (unsigned int)recv_len)) {
        fprintf(stderr, "kernel_netlink_interface: Invalid Netlink message (NLMSG_OK failed). recv_len=%zd, nlmsg_len=%u\n",
                recv_len, nlh->nlmsg_len);
        free(nlh);
        return -1;
    }

    // We expect the actual data payload now
    netlink_ipc_msg_downstream_t *kernel_response = (netlink_ipc_msg_downstream_t *)NLMSG_DATA(nlh);

    // Check if the actual data received is what we expect.
    // NLMSG_PAYLOAD gives the length of the payload section.
    if (NLMSG_PAYLOAD(nlh, 0) < sizeof(netlink_ipc_msg_downstream_t)) {
        fprintf(stderr, "kernel_netlink_interface: Received payload too short for downstream message. Payload_len=%d, Expected_len=%zu\n",
                NLMSG_PAYLOAD(nlh, 0), sizeof(netlink_ipc_msg_downstream_t));
        free(nlh);
        return -1;
    }

    memcpy(down_payload, kernel_response, sizeof(netlink_ipc_msg_downstream_t));
    netlink_transform_data_buffer((unsigned char *)down_payload, sizeof(netlink_ipc_msg_downstream_t));

    if (down_payload->error_code != 0) {
        fprintf(stderr, "kernel_netlink_interface: Kernel module logic error %d for request: type=%d, target_id=%d, offset=0x%lx\n",
                down_payload->error_code,
                up_payload->type, up_payload->target_id, up_payload->data_offset);
        // No free(nlh) here if returning error_code, let it be freed at the end.
    }

    free(nlh);
    return down_payload->error_code; // Success if 0, kernel error code otherwise
}
