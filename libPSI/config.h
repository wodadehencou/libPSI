#pragma once
#include <cryptoTools/Common/config.h>
#include <libOTe/config.h>

#if LIBOTE_VERSION < 10000
Config ERROR: libOTe is too old.
#endif

#define ON 1

#if ENABLE_RELIC !=  OFF
static_assert(0,"ENABLE_RELIC flag does not match with libOTe");
#endif

#if ENABLE_MIRACL !=  OFF
static_assert(0,"ENABLE_MIRACL flag does not match with libOTe");
#endif

#if !defined(_MSC_VER) && (ENABLE_SIMPLESTOT_ASM !=  OFF)
static_assert(0,"ENABLE_SIMPLESTOT_ASM flag does not match with libOTe");
#endif

#if !defined(_MSC_VER) && (ENABLE_MR_KYBER !=  OFF)
static_assert(0,"ENABLE_MR_KYBER flag does not match with libOTe");
#endif

// build the library with DCW PSI enabled
/* #undef ENABLE_DCW_PSI */

// build the library with DKT PSI enabled
/* #undef ENABLE_DKT_PSI */

// build the library with GRR PSI enabled
/* #undef ENABLE_GRR_PSI */

// build the library with RR16 PSI enabled
/* #undef ENABLE_RR16_PSI */

// build the library with RR17 PSI enabled
/* #undef ENABLE_RR17_PSI */

// build the library with RR17 PSI enabled
/* #undef ENABLE_RR17B_PSI */

// build the library with KKRT PSI enabled
#define ENABLE_KKRT_PSI  ON

// build the library with ECDH PSI enabled
/* #undef ENABLE_ECDH_PSI */

// build the library with DRRN PSI enabled
/* #undef ENABLE_DRRN_PSI */

// build the library with PRTY PSI enabled
/* #undef ENABLE_PRTY_PSI */


#undef ON
