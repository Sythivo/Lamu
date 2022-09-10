cmake_minimum_required(VERSION 3.12.2)

project(Lamu)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CONFIGURATION_TYPES "Debug;Release"
    CACHE STRING "Configuration types" FORCE)

add_executable(Lamu
  Core/File/file_system.cpp
  Core/File/file_system.h
  Core/lamu.h
  Core/lamu_base.cpp
  Core/lamu_http.cpp
  Core/lamu_import.cpp
  Core/lamu_scheduler.cpp
  Core/Libraries/cpp-httplib/client/client.cpp
  Core/Libraries/cpp-httplib/client/client.h
  Core/Libraries/cpp-httplib/http.h
  Core/Libraries/cpp-httplib/lib.h
  Core/Libraries/cpp-httplib/server/server.cpp
  Core/Libraries/cpp-httplib/server/server.h
  Core/Libraries/HTTP/http.h
  Core/task_scheduler.h
  Luau/Ast/Ast.cpp
  Luau/Ast/Ast.h
  Luau/Ast/Confusables.cpp
  Luau/Ast/Confusables.h
  Luau/Ast/DenseHash.h
  Luau/Ast/Lexer.cpp
  Luau/Ast/Lexer.h
  Luau/Ast/Location.cpp
  Luau/Ast/Location.h
  Luau/Ast/ParseOptions.h
  Luau/Ast/Parser.cpp
  Luau/Ast/Parser.h
  Luau/Ast/ParseResult.h
  Luau/Ast/StringUtils.cpp
  Luau/Ast/StringUtils.h
  Luau/Ast/TimeTrace.cpp
  Luau/Ast/TimeTrace.h
  Luau/Common/Bytecode.h
  Luau/Common/Common.h
  Luau/Common/ExperimentalFlags.h
  Luau/Compiler/BuiltinFolding.cpp
  Luau/Compiler/BuiltinFolding.h
  Luau/Compiler/Builtins.cpp
  Luau/Compiler/Builtins.h
  Luau/Compiler/BytecodeBuilder.cpp
  Luau/Compiler/BytecodeBuilder.h
  Luau/Compiler/Compiler.cpp
  Luau/Compiler/Compiler.h
  Luau/Compiler/ConstantFolding.cpp
  Luau/Compiler/ConstantFolding.h
  Luau/Compiler/CostModel.cpp
  Luau/Compiler/CostModel.h
  Luau/Compiler/lcode.cpp
  Luau/Compiler/luacode.h
  Luau/Compiler/TableShape.cpp
  Luau/Compiler/TableShape.h
  Luau/Compiler/ValueTracking.cpp
  Luau/Compiler/ValueTracking.h
  Luau/VM/lapi.cpp
  Luau/VM/lapi.h
  Luau/VM/laux.cpp
  Luau/VM/lbaselib.cpp
  Luau/VM/lbitlib.cpp
  Luau/VM/lbuiltins.cpp
  Luau/VM/lbuiltins.h
  Luau/VM/lbytecode.h
  Luau/VM/lcommon.h
  Luau/VM/lcorolib.cpp
  Luau/VM/ldblib.cpp
  Luau/VM/ldebug.cpp
  Luau/VM/ldebug.h
  Luau/VM/ldo.cpp
  Luau/VM/ldo.h
  Luau/VM/lfunc.cpp
  Luau/VM/lfunc.h
  Luau/VM/lgc.cpp
  Luau/VM/lgc.h
  Luau/VM/lgcdebug.cpp
  Luau/VM/linit.cpp
  Luau/VM/lmathlib.cpp
  Luau/VM/lmem.cpp
  Luau/VM/lmem.h
  Luau/VM/lnumprint.cpp
  Luau/VM/lnumutils.h
  Luau/VM/lobject.cpp
  Luau/VM/lobject.h
  Luau/VM/loslib.cpp
  Luau/VM/lperf.cpp
  Luau/VM/lstate.cpp
  Luau/VM/lstate.h
  Luau/VM/lstring.cpp
  Luau/VM/lstring.h
  Luau/VM/lstrlib.cpp
  Luau/VM/ltable.cpp
  Luau/VM/ltable.h
  Luau/VM/ltablib.cpp
  Luau/VM/ltm.cpp
  Luau/VM/ltm.h
  Luau/VM/lua.h
  Luau/VM/luaconf.h
  Luau/VM/lualib.h
  Luau/VM/ludata.cpp
  Luau/VM/ludata.h
  Luau/VM/lutf8lib.cpp
  Luau/VM/lvm.h
  Luau/VM/lvmexecute.cpp
  Luau/VM/lvmload.cpp
  Luau/VM/lvmutils.cpp
  Main.cpp
)

IF (WIN32) # Windows
  # Placeholder
ELSE() # Other Linux/Mac
    IF(UNIX)
        find_library(LIBPTHREAD pthread)
        IF(LIBPTHREAD)
            target_link_libraries(Lamu PRIVATE pthread)
        ENDIF()
    ENDIF()
ENDIF()

# Preprocessor definitions
target_compile_definitions(Lamu PRIVATE
  $<$<CONFIG:Debug>:_UNICODE;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS>
  $<$<CONFIG:Release>:_UNICODE;_RELEASE;_CONSOLE;_CRT_SECURE_NO_WARNINGS>
)

# SDL check
target_compile_options(Lamu PRIVATE
  "$<$<CONFIG:Debug>:/sdl>"
  "$<$<CONFIG:Release>:/sdl>"
)
