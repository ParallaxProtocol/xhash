# xhash: C/C++ implementation of XHash, the Ethereum Proof of Work algorithm.
# Copyright 2021 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

include(HunterGate)

if(NOT WIN32)
  # Outside of Windows build only Release packages.
  set(HUNTER_CONFIGURATION_TYPES Release
        CACHE STRING "Build type of the Hunter packages")
endif()

HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.26.6.tar.gz"
    SHA1 "e70c29f878f5d5f5cdf1b9ccd628fb872e8624a8"
    LOCAL
)
