# SPDX-License-Identifier: MIT
use strict;
use warnings;
use Config;
use JSON::PP;
use DynaLoader;
my $root = shift;
die "candidate version required\n" unless "$^V" eq 'v5.42.3';
for my $module (qw(DB_File GDBM_File Compress::Raw::Zlib Compress::Raw::Bzip2 threads)) {
    (my $file = "$module.pm") =~ s{::}{/}g;
    require $file;
}
die "staged Config required\n" unless $INC{'Config.pm'} eq "$root/usr/lib/perl5/5.42/core_perl/Config.pm";
die "staged C extension objects required\n" unless @DynaLoader::dl_shared_objects >= 5;
for my $path (@DynaLoader::dl_shared_objects) {
    die "foreign C extension: $path\n" unless index($path, "$root/usr/lib/perl5/5.42/core_perl/") == 0;
}
print JSON::PP->new->canonical->encode({ version => "$^V", config => $INC{'Config.pm'},
    shared_objects => \@DynaLoader::dl_shared_objects, scope => 'staged interpreter/core only; no installed PATH or external XS acceptance' }), "\n";
