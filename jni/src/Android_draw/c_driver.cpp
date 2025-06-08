#include "c_driver.h"
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>  // For isalnum

// Global driver instance definition
static c_driver global_driver_instance; // Static to keep it local to this translation unit
c_driver *driver = &global_driver_instance; // Global pointer

c_driver::c_driver() : current_pid(-1), initialized_properly(false) {
    if (initialize_netlink_connection() == 0) {
        initialized_properly = true;
        // fprintf(stderr, "c_driver: Netlink connection initialized successfully.\n");
    } else {
        // This error is critical, should be logged prominently.
        fprintf(stderr, "CRITICAL: c_driver: Failed to initialize Netlink connection with kernel module.\n");
    }
}

c_driver::~c_driver() {
    close_netlink_connection();
    // fprintf(stderr, "c_driver: Netlink connection closed.\n");
}

void c_driver::initialize_for_pid(pid_t target_pid) {
    this->current_pid = target_pid;
    if (target_pid == -1) {
         fprintf(stderr, "c_driver::initialize_for_pid: Initialized with invalid PID -1.\n");
    }
}

uintptr_t c_driver::get_module_base_address(const char* module_name) {
    if (!initialized_properly) {
        fprintf(stderr, "c_driver::get_module_base_address: Driver not initialized properly (module: %s).\n", module_name);
        return 0;
    }
    if (this->current_pid == -1) {
        fprintf(stderr, "c_driver::get_module_base_address: PID not initialized (module: %s).\n", module_name);
        return 0;
    }
    if (module_name == nullptr || module_name[0] == '\0') {
        fprintf(stderr, "c_driver::get_module_base_address: Module name is null or empty.\n");
        return 0;
    }

    netlink_ipc_msg_upstream_t up_payload;
    memset(&up_payload, 0, sizeof(up_payload));
    up_payload.type = NETLINK_REQ_TYPE_QUERY_BASE;
    up_payload.target_id = this->current_pid;
    strncpy(up_payload.object_label, module_name, sizeof(up_payload.object_label) - 1);
    up_payload.object_label[sizeof(up_payload.object_label) - 1] = '\0';
    memcpy(up_payload.auth_key_data, g_netlink_channel_auth_sequence, sizeof(g_netlink_channel_auth_sequence));

    netlink_ipc_msg_downstream_t down_payload;
    memset(&down_payload, 0, sizeof(down_payload));

    if (execute_netlink_ipc_transaction(&up_payload, &down_payload) == 0 && down_payload.error_code == 0) {
        return down_payload.value;
    }
    // fprintf(stderr, "c_driver::get_module_base_address: Failed for module %s (PID: %d).\n", module_name, this->current_pid);
    return 0;
}

bool c_driver::read_memory(uintptr_t addr, void *buffer, size_t size) {
    if (!initialized_properly) {
        // fprintf(stderr, "c_driver::read_memory: Driver not initialized properly (addr: 0x%lx).\n", (unsigned long)addr);
        return false;
    }
     if (this->current_pid == -1) {
        // fprintf(stderr, "c_driver::read_memory: PID not initialized (addr: 0x%lx).\n", (unsigned long)addr);
        return false;
    }
    if (buffer == nullptr) {
        fprintf(stderr, "c_driver::read_memory: Output buffer is null (addr: 0x%lx).\n", (unsigned long)addr);
        return false;
    }
    if (addr == 0) {
        // fprintf(stderr, "c_driver::read_memory: Attempt to read from null address.\n");
        return false; // Reading from address 0 is usually an error.
    }

    netlink_ipc_msg_upstream_t up_payload;
    memset(&up_payload, 0, sizeof(up_payload));

    if (size == sizeof(int32_t)) {
        up_payload.type = NETLINK_REQ_TYPE_FETCH_INT;
    } else if (size == sizeof(uintptr_t)) { // Assuming float is read as uintptr_t size via netlink
        up_payload.type = NETLINK_REQ_TYPE_FETCH_PTR; // Re-evaluate if float needs specific type
    } else if (size == sizeof(float)) { // Added specific handling for float if it's different from uintptr_t
         up_payload.type = NETLINK_REQ_TYPE_FETCH_PTR; // Or a new NETLINK_REQ_TYPE_FETCH_FLOAT if defined
    } else {
        fprintf(stderr, "c_driver::read_memory: Unsupported read size %zu for address 0x%lx\n", size, (unsigned long)addr);
        return false;
    }

    up_payload.target_id = this->current_pid;
    up_payload.data_offset = addr;
    memcpy(up_payload.auth_key_data, g_netlink_channel_auth_sequence, sizeof(g_netlink_channel_auth_sequence));

    netlink_ipc_msg_downstream_t down_payload;
    memset(&down_payload, 0, sizeof(down_payload));

    if (execute_netlink_ipc_transaction(&up_payload, &down_payload) == 0 && down_payload.error_code == 0) {
        // Important: Ensure that the value from down_payload.value is correctly copied
        // to the buffer, respecting the size.
        if (size == sizeof(int32_t)) {
            memcpy(buffer, &down_payload.value, sizeof(int32_t));
        } else if (size == sizeof(uintptr_t)) {
            memcpy(buffer, &down_payload.value, sizeof(uintptr_t));
        } else if (size == sizeof(float)) { // Handle float copy
            memcpy(buffer, &down_payload.value, sizeof(float));
        }
        return true;
    }
    // fprintf(stderr, "c_driver::read_memory: Failed for address 0x%lx, size %zu (PID: %d).\n", (unsigned long)addr, size, this->current_pid);
    return false;
}

bool c_driver::write_memory(uintptr_t addr, const void *buffer, size_t size) {
    if (!initialized_properly) {
        // fprintf(stderr, "c_driver::write_memory: Driver not initialized properly (addr: 0x%lx).\n", (unsigned long)addr);
        return false;
    }
    if (this->current_pid == -1) {
        // fprintf(stderr, "c_driver::write_memory: PID not initialized (addr: 0x%lx).\n", (unsigned long)addr);
        return false;
    }
    if (buffer == nullptr) {
        fprintf(stderr, "c_driver::write_memory: Input buffer is null (addr: 0x%lx).\n", (unsigned long)addr);
        return false;
    }
     if (addr == 0) {
        // fprintf(stderr, "c_driver::write_memory: Attempt to write to null address.\n");
        return false;
    }

    netlink_ipc_msg_upstream_t up_payload;
    memset(&up_payload, 0, sizeof(up_payload));

    if (size == sizeof(int32_t)) {
        up_payload.type = NETLINK_REQ_TYPE_WRITE_INT;
        memcpy(&up_payload.value_to_write, buffer, sizeof(int32_t));
    } else if (size == sizeof(uintptr_t)) { // Assuming float is written as uintptr_t size
        up_payload.type = NETLINK_REQ_TYPE_WRITE_PTR;
        memcpy(&up_payload.value_to_write, buffer, sizeof(uintptr_t));
    } else if (size == sizeof(float)) { // Added specific handling for float
        up_payload.type = NETLINK_REQ_TYPE_WRITE_PTR; // Or a new NETLINK_REQ_TYPE_WRITE_FLOAT if defined
        memcpy(&up_payload.value_to_write, buffer, sizeof(float));
    } else {
        fprintf(stderr, "c_driver::write_memory: Unsupported write size %zu for address 0x%lx\n", size, (unsigned long)addr);
        return false;
    }

    up_payload.target_id = this->current_pid;
    up_payload.data_offset = addr;
    memcpy(up_payload.auth_key_data, g_netlink_channel_auth_sequence, sizeof(g_netlink_channel_auth_sequence));

    netlink_ipc_msg_downstream_t down_payload;
    memset(&down_payload, 0, sizeof(down_payload));

    if (execute_netlink_ipc_transaction(&up_payload, &down_payload) == 0 && down_payload.error_code == 0) {
        return true;
    }
    // fprintf(stderr, "c_driver::write_memory: Failed for address 0x%lx, size %zu (PID: %d).\n", (unsigned long)addr, size, this->current_pid);
    return false;
}

// Implementation of helper functions
pid_t getPID(const char* PackageName) {
    FILE* fp;
    pid_t pid_val = -1;
    char cmd[280]; // Increased buffer size for "pidof " + PackageName

    if (PackageName == nullptr || strlen(PackageName) == 0 || strlen(PackageName) > 255) {
        fprintf(stderr, "getPID: Invalid PackageName (null, empty, or too long).\n");
        return -1;
    }

    const char* p = PackageName;
    while (*p) {
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' && *p != '-') { // Allowed '-'
                 fprintf(stderr, "getPID: Invalid character in PackageName: %s\n", PackageName);
                 return -1;
            }
            p++;
    }

    snprintf(cmd, sizeof(cmd), "pidof %s", PackageName);

    fp = popen(cmd, "r");
    if (fp) {
        if (fscanf(fp, "%d", &pid_val) == 1) {
            // Successfully read PID
        } else {
            pid_val = -1;
        }
        pclose(fp);
    } else {
        // perror("getPID popen failed"); // This can be noisy if process not found
    }
    return pid_val;
}

uintptr_t ReadValue(uintptr_t addr) {
    return driver->read_typed<uintptr_t>(addr);
}

int32_t ReadInt32(uintptr_t addr) {
    return driver->read_typed<int32_t>(addr);
}

float ReadFloat(uintptr_t addr) {
    return driver->read_typed<float>(addr);
}

bool WriteInt32(uintptr_t addr, int32_t value) {
    return driver->write_typed<int32_t>(addr, value);
}

bool WriteFloat(uintptr_t addr, float value) {
    return driver->write_typed<float>(addr, value);
}

uintptr_t getModuleBase(const char* module_name) {
    return driver->get_module_base_address(module_name);
}
