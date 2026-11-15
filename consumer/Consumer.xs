/* SPDX-License-Identifier: MIT */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#if PERL_REVISION != 5 || PERL_VERSION != 42 || PERL_SUBVERSION != 3 || IVSIZE != 8
#error "This fixture requires the admitted Perl 5.42.3 headers and 64-bit IV"
#endif

MODULE = CachyAsahi::Perl5423::Consumer PACKAGE = CachyAsahi::Perl5423::Consumer
PROTOTYPES: DISABLE

SV *
scalar_roundtrip(value)
    SV *value
  CODE:
    RETVAL = newSVsv(value);
  OUTPUT:
    RETVAL

IV
iv_roundtrip(value)
    IV value
  CODE:
    RETVAL = value;
  OUTPUT:
    RETVAL

SV *
array_roundtrip(value)
    SV *value
  PREINIT:
    AV *source, *copy;
    SSize_t i;
    SV **item;
  CODE:
    if (!SvROK(value) || SvTYPE(SvRV(value)) != SVt_PVAV) croak("array reference required");
    source = (AV *)SvRV(value); copy = newAV();
    for (i = 0; i <= av_len(source); ++i) {
        item = av_fetch(source, i, 0);
        av_push(copy, item ? newSVsv(*item) : newSV(0));
    }
    RETVAL = newRV_noinc((SV *)copy);
  OUTPUT:
    RETVAL

SV *
native_info()
  PREINIT:
    HV *info;
  CODE:
    info = newHV();
    hv_stores(info, "perl", newSVpvf("%d.%d.%d", PERL_REVISION, PERL_VERSION, PERL_SUBVERSION));
    hv_stores(info, "api", newSVpvf("%d.%d.%d", PERL_API_REVISION, PERL_API_VERSION, PERL_API_SUBVERSION));
    hv_stores(info, "iv_bytes", newSViv((IV)sizeof(IV)));
    RETVAL = newRV_noinc((SV *)info);
  OUTPUT:
    RETVAL
