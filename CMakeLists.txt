cmake_minimum_required(VERSION 2.8)

# VitaSDK defines
if( NOT DEFINED CMAKE_TOOLCHAIN_FILE )
  if( DEFINED ENV{VITASDK} )
  set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
  message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

# Project start
project(ShaRKF00D)
include("${VITASDK}/share/vita.cmake" REQUIRED)
set(VITA_APP_NAME "ShaRKF00D")
set(VITA_TITLEID  "SHARKF00D")
set(VITA_VERSION  "01.20")

# Flags and includes
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=gnu11 -Wall -O0 -Wno-unused-variable -Wno-unused-but-set-variable -Wno-format-truncation -fno-lto")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++11 -fno-rtti -fno-exceptions")
set(VITA_MKSFOEX_FLAGS "${VITA_MKSFOEX_FLAGS} -d PARENTAL_LEVEL=1 -d ATTRIBUTE2=12")
set(VITA_MAKE_FSELF_FLAGS "${VITA_MAKE_FSELF_FLAGS} -a 0x2808000000000000")

add_subdirectory(modules/kernel)
add_subdirectory(modules/user)
add_subdirectory(modules/patch)
add_subdirectory(modules/kplugin)
add_subdirectory(modules/uplugin)

include_directories(
  modules/kernel
  modules/user
)

link_directories(
  ${CMAKE_CURRENT_BINARY_DIR}
)

FUNCTION(ADD_RESOURCES out_var)
  SET(result)
  FOREACH(ref_f ${ARGN})
  if (IS_ABSOLUTE "${ref_f}")
    SET(out_f "${ref_f}.o")
    STRING(REPLACE "${CMAKE_CURRENT_BINARY_DIR}/" "" in_f "${ref_f}")
    SET(work_dir "${CMAKE_CURRENT_BINARY_DIR}")
  else()
    SET(out_f "${CMAKE_CURRENT_BINARY_DIR}/${ref_f}.o")
    SET(in_f "${ref_f}")
    SET(work_dir "${CMAKE_SOURCE_DIR}")
  endif()
  GET_FILENAME_COMPONENT(out_dir ${out_f} DIRECTORY)
  ADD_CUSTOM_COMMAND(OUTPUT ${out_f}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${out_dir}
    COMMAND ${CMAKE_LINKER} -r -b binary -o ${out_f} ${in_f}
    DEPENDS ${ref_f}
    WORKING_DIRECTORY ${work_dir}
    COMMENT "Building resource ${out_f}"
    VERBATIM
    )
  LIST(APPEND result ${out_f})
  ENDFOREACH()
  SET(${out_var} "${result}" PARENT_SCOPE)
ENDFUNCTION()

file(GLOB res_files RELATIVE
  ${CMAKE_SOURCE_DIR}
  resources/umass.skprx
  resources/default/*.png
  resources/default/*.txt
  resources/electron/*.png
  resources/electron/*.txt
  resources/*.png
  resources/*.txt
  resources/*.bin
)

add_resources(sharkf00d_res
  ${res_files}
  ${CMAKE_CURRENT_BINARY_DIR}/modules/kernel/kernel.skprx
  ${CMAKE_CURRENT_BINARY_DIR}/modules/user/user.suprx
  ${CMAKE_CURRENT_BINARY_DIR}/modules/patch/patch.skprx
  ${CMAKE_CURRENT_BINARY_DIR}/modules/kplugin/kentente.skprx
  ${CMAKE_CURRENT_BINARY_DIR}/modules/uplugin/userAllied.suprx
)

add_executable(ShaRKF00D
  ${sharkf00d_res}
  sbrk.c
  main.c
  file.c
  pfs.c
  sha256.c
  aes.c
  debugscreen/debugScreen.c
)

add_dependencies(ShaRKF00D sharkf00d_user_stubs)
add_dependencies(ShaRKF00D kernel.skprx)
add_dependencies(ShaRKF00D user.suprx)
add_dependencies(ShaRKF00D patch.skprx)
add_dependencies(ShaRKF00D kentente.skprx)
add_dependencies(ShaRKF00D userAllied.suprx)

target_link_libraries(ShaRKF00D
  ${CMAKE_CURRENT_BINARY_DIR}/modules/user/vitashell_user_stubs/libVitaShellUser_stub_weak.a
  ${CMAKE_CURRENT_BINARY_DIR}/modules/uplugin/userAllied-stubs/libuserAllied_stub_weak.a
  z
  m
  c
  taihen_stub
  SceAppMgr_stub
  SceAppUtil_stub
  SceCommonDialog_stub
  SceCtrl_stub
  SceDisplay_stub
  SceFios2_stub
  SceLibKernel_stub
  SceMtpIfDriver_stub
  SceNpDrm_stub
  SceRegistryMgr_stub
  SceShellSvc_stub
  SceSysmodule_stub
  ScePower_stub
  ScePromoterUtil_stub
  SceTouch_stub
  SceVshBridge_stub
)

# Create Vita artifacts
vita_create_self(eboot.bin ShaRKF00D UNSAFE)
vita_create_vpk(ShaRKF00D.vpk ${VITA_TITLEID} eboot.bin
  VERSION ${VITA_VERSION}
  NAME ${VITA_APP_NAME}
  FILE pkg/sce_sys/icon0.png sce_sys/icon0.png
       pkg/sce_sys/livearea/contents/bg.png sce_sys/livearea/contents/bg.png
       pkg/sce_sys/livearea/contents/startup.png sce_sys/livearea/contents/startup.png
       pkg/sce_sys/livearea/contents/template.xml sce_sys/livearea/contents/template.xml
       ${CMAKE_CURRENT_BINARY_DIR}/modules/kernel/kernel.skprx sce_module/kernel.skprx
       ${CMAKE_CURRENT_BINARY_DIR}/modules/patch/patch.skprx sce_module/patch.skprx
       ${CMAKE_CURRENT_BINARY_DIR}/modules/user/user.suprx sce_module/user.suprx
       ${CMAKE_CURRENT_BINARY_DIR}/modules/kplugin/kentente.skprx sce_module/kentente.skprx
       ${CMAKE_CURRENT_BINARY_DIR}/modules/uplugin/userAllied.suprx sce_module/userAllied.suprx
)

add_custom_target(release
  COMMAND cp eboot.bin ../release/eboot.bin
  COMMAND cp ShaRKF00D.vpk_param.sfo ../release/param.sfo
  COMMAND cp ShaRKF00D.vpk ../release/ShaRKF00D.vpk
  COMMAND cp ../pkg/sce_sys/livearea/contents/template.xml ../release/template.xml
  DEPENDS eboot.bin
  DEPENDS ShaRKF00D.vpk
  DEPENDS ShaRKF00D.vpk_param.sfo
)

add_custom_target(send
  COMMAND curl -T eboot.bin ftp://$(PSVITAIP):1337/ux0:/app/${VITA_TITLEID}/
  DEPENDS eboot.bin
)

add_custom_target(copy
  COMMAND cp eboot.bin G:/app/${VITA_TITLEID}/eboot.bin
  DEPENDS eboot.bin
)
