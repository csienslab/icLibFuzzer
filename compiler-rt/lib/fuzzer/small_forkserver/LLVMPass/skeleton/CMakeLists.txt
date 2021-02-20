add_library(ForkserverPass MODULE
    Forkserver.cpp
)

add_library(ParentPass MODULE
    Parent.cpp
)

# Use C++11 to compile your pass (i.e., supply -std=c++11).
# target_compile_features(ForkserverPass PRIVATE cxx_range_for cxx_auto_type)
# target_compile_features(ParentPass PRIVATE cxx_range_for cxx_auto_type)

# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
set_target_properties(ForkserverPass PROPERTIES
    COMPILE_FLAGS "-fno-rtti -std=c++1y"
)
set_target_properties(ParentPass PROPERTIES
    COMPILE_FLAGS "-fno-rtti -std=c++1y"
)


# Get proper shared-library behavior (where symbols are not necessarily
# resolved when the shared library is linked) on OS X.
if(APPLE)
    set_target_properties(ForkserverPass PROPERTIES
        LINK_FLAGS "-undefined dynamic_lookup"
    )
    set_target_properties(ParentPass PROPERTIES
        LINK_FLAGS "-undefined dynamic_lookup"
    )
endif(APPLE)
