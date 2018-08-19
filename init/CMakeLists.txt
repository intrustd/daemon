cmake_minimum_required(VERSION 2.6)
PROJECT(storkd-init)

ADD_EXECUTABLE(persona-init persona.c init_common.c)
TARGET_COMPILE_OPTIONS(persona-init PUBLIC -I../common)
ADD_EXECUTABLE(app-instance-init app_instance.c init_common.c)
TARGET_COMPILE_OPTIONS(app-instance-init PUBLIC -I../common)
