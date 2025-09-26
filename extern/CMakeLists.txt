# add header-only library target for tqdm (a progress bar library)
add_library(cpptqdm INTERFACE)
target_include_directories(cpptqdm INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/cpptqdm)
