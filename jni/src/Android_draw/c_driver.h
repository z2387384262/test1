#ifndef C_DRIVER_H
#define C_DRIVER_H

#include <sys/types.h> // For pid_t
#include <stdint.h>    // For uintptr_t, int32_t
#include <string.h>    // For strncpy, memcpy
#include <stdio.h>     // For fprintf, perror
#include <ctype.h>     // For isalnum in getPID (though getPID is in .cpp)

// Adjust path as necessary. If c_driver.h is in jni/src/Android_draw/
// and kernel_netlink_interface.h is in jni/src/, then this path is correct.
#include "../kernel_netlink_interface.h"

class c_driver {
private:
    pid_t current_pid;
    bool initialized_properly;

public:
    c_driver();
    ~c_driver();

    void initialize_for_pid(pid_t target_pid);

    bool read_memory(uintptr_t addr, void *buffer, size_t size);
    bool write_memory(uintptr_t addr, const void *buffer, size_t size); // buffer is const void* for write
    uintptr_t get_module_base_address(const char* module_name);

    template <typename T>
    T read_typed(uintptr_t addr) {
        T res{};
        if (!initialized_properly) {
            // fprintf(stderr, "c_driver::read_typed: Driver not initialized properly for addr 0x%lx.\n", (unsigned long)addr);
            return res;
        }
        if (this->read_memory(addr, &res, sizeof(T))) {
            return res;
        }
        // fprintf(stderr, "c_driver::read_typed: read_memory failed for addr 0x%lx.\n", (unsigned long)addr);
        return res;
    }

    template <typename T>
    bool write_typed(uintptr_t addr, T value) {
        if (!initialized_properly) {
            // fprintf(stderr, "c_driver::write_typed: Driver not initialized properly for addr 0x%lx.\n", (unsigned long)addr);
            return false;
        }
        return this->write_memory(addr, &value, sizeof(T));
    }
};

// Global instance declaration
extern c_driver *driver;

// Helper function declarations (to be implemented in c_driver.cpp)
pid_t getPID(const char* PackageName);
uintptr_t ReadValue(uintptr_t addr);
int32_t ReadInt32(uintptr_t addr);
float ReadFloat(uintptr_t addr);
uint32_t ReadDword(uintptr_t addr);
bool WriteInt32(uintptr_t addr, int32_t value);
bool WriteFloat(uintptr_t addr, float value);
uintptr_t getModuleBase(const char* module_name);

#endif // C_DRIVER_H
