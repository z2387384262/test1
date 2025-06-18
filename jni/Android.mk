LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := 1.sh
LOCAL_CPPFLAGS := -w -std=c++17

# 添加LLVM混淆选项在这里
#LOCAL_CPPFLAGS += -mllvm -sub -mllvm -sobf -mllvm -bcf
#LOCAL_CPPFLAGS += -mllvm -sub -mllvm -sobf -mllvm -split -mllvm -bcf  -mllvm -fla
LOCAL_C_INCLUDES +=$(LOCAL_PATH)/include
LOCAL_C_INCLUDES +=$(LOCAL_PATH)/include/Android_draw
LOCAL_C_INCLUDES +=$(LOCAL_PATH)/include/Android_touch
LOCAL_C_INCLUDES +=$(LOCAL_PATH)/include/ImGui
LOCAL_C_INCLUDES +=$(LOCAL_PATH)/include/native_surface
LOCAL_C_INCLUDES +=$(LOCAL_PATH)/include/native_surface/aosp

LOCAL_SRC_FILES :=     src/main.cpp     src/kernel_netlink_interface.cpp     src/Android_draw/c_driver.cpp     src/Android_draw/draw.cpp     src/res/cJSON.c

# Add ImGui files using wildcard (assuming they are all .cpp files)
# If there are .c files, they need to be added separately or the pattern adjusted
FILE_LIST_IMGUI := $(wildcard $(LOCAL_PATH)/src/ImGui/*.cpp)
LOCAL_SRC_FILES += $(FILE_LIST_IMGUI:$(LOCAL_PATH)/%=%)

# Add Android_touch files using wildcard
FILE_LIST_TOUCH := $(wildcard $(LOCAL_PATH)/src/Android_touch/*.cpp)
LOCAL_SRC_FILES += $(FILE_LIST_TOUCH:$(LOCAL_PATH)/%=%)

# If stb_image.c is used by ImGui and is a .c file, it needs to be added.
# Check if src/ImGui/stb_image.cpp exists, if so the above is fine.
# If it's src/ImGui/stb_image.c, it won't be picked up by *.cpp
# From previous ls, it's src/ImGui/stb_image.cpp, so the wildcard *.cpp for ImGui is fine.

LOCAL_LDFLAGS += -lEGL -lGLESv2 -lGLESv3 -landroid -llog
include $(BUILD_EXECUTABLE)



# 控制流扁平化
# -mllvm -fla：激活控制流扁平化
# -mllvm -split：激活基本块分割。在一起使用时改善展平。
# -mllvm -split_num=3：如果激活了传递，则在每个基本块上应用3次。默认值：1

# 指令替换
# -mllvm -sub：激活指令替换
# -mllvm -sub_loop=3：如果激活了传递，则在函数上应用3次。默认值：1

# 虚假控制流程
# -mllvm -bcf：激活虚假控制流程
# -mllvm -bcf_loop=3：如果激活了传递，则在函数上应用3次。默认值：1
# -mllvm -bcf_prob=40：如果激活了传递，基本块将以40％的概率进行模糊处理。默认值：30

# 字符串加密
# -mllvm -sobf：编译时候添加选项开启字符串加密
# -mllvm -seed=0xabcdefg：指定随机数生成器种子流程

# 如果你对强度没有要求，只是单纯的简单混淆，可以使用下面这个.
# #FAST PROTECTION + SMALL SIZE:
# LOCAL_CPPFLAGS += -mllvm -sub -mllvm -sobf -mllvm -split -mllvm -bcf  -mllvm -fla 

# 如果你想高强度且不嫌打包时间慢可以使用下面.
# #SLOW PROTECTION + BIG SIZE :
# LOCAL_CPPFLAGS += -mllvm -sub -mllvm -sub_loop=3 -mllvm -sobf -mllvm -split -mllvm -split_num=3 -mllvm -bcf -mllvm -bcf_loop=1 -mllvm -bcf_prob=10 -mllvm -fla
