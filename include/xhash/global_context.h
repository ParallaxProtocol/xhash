/* xhash: C/C++ implementation of XHash, the Ethereum Proof of Work algorithm.
 * Copyright 2018 Pawel Bylica.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include <xhash/xhash.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get global shared epoch context.
 */
const struct xhash_epoch_context* xhash_get_global_epoch_context(int epoch_number) noexcept;

/**
 * Get global shared epoch context with full dataset initialized.
 */
const struct xhash_epoch_context_full* xhash_get_global_epoch_context_full(
    int epoch_number) noexcept;

#ifdef __cplusplus
}
#endif
