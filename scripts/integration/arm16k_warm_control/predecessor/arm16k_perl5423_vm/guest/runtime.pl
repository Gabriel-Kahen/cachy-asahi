# SPDX-License-Identifier: MIT
use strict;
use warnings;
use Config;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use DB_File;
use GDBM_File;
use Fcntl qw(O_RDWR O_CREAT);
use Compress::Raw::Zlib;
use Compress::Raw::Bzip2;
use threads;
use threads::shared;
use DynaLoader;
my $arch='/usr/lib/perl5/5.42/core_perl';
for my $module (qw(Config.pm DB_File.pm GDBM_File.pm Compress/Raw/Zlib.pm Compress/Raw/Bzip2.pm threads.pm threads/shared.pm)) {
    die "foreign module $module" unless ($INC{$module}//'') eq "$arch/$module";
}
my %loaded=map { $_=>1 } @DynaLoader::dl_shared_objects;
for my $object (qw(auto/DB_File/DB_File.so auto/GDBM_File/GDBM_File.so auto/Compress/Raw/Zlib/Zlib.so auto/Compress/Raw/Bzip2/Bzip2.so auto/threads/threads.so)) {
    die "missing actual candidate XS $object" unless $loaded{"$arch/$object"};
}
for my $object (keys %loaded) { die "foreign XS $object" unless index($object,"$arch/")==0; }
open my $maps,'<','/proc/self/maps' or die "actual libperl maps: $!";
my @libperl=grep { m{ /usr/lib/perl5/5[.]42/core_perl/CORE/libperl[.]so$} } <$maps>;
close $maps or die $!;die 'actual shared libperl mapping required' unless @libperl;
die 'version' unless "$^V" eq 'v5.42.3';
die 'shared/threaded' unless $Config{useshrplib} eq 'true' && $Config{useithreads} eq 'define';
my %paths = (prefix=>'/usr', privlib=>'/usr/share/perl5/core_perl', archlib=>'/usr/lib/perl5/5.42/core_perl',
 vendorlib=>'/usr/share/perl5/vendor_perl', vendorarch=>'/usr/lib/perl5/5.42/vendor_perl',
 sitelib=>'/usr/local/share/perl5/site_perl', sitearch=>'/usr/local/lib/perl5/5.42/site_perl', scriptdir=>'/usr/bin/core_perl');
for (keys %paths) { die "path $_" unless $Config{$_} eq $paths{$_}; }
my $text = "Perl5423 ARM16K functional data\n" x 128;
my %db; tie %db, 'DB_File', 'db-file', O_RDWR|O_CREAT, 0600, $DB_HASH or die "DB_File: $!";
$db{probe}=$text; untie %db;
tie %db, 'DB_File', 'db-file', O_RDWR, 0600, $DB_HASH or die $!;
die 'DB_File roundtrip' unless $db{probe} eq $text; untie %db;
my %g; tie %g, 'GDBM_File', 'gdbm-file', GDBM_WRCREAT, 0600 or die "GDBM: $!";
$g{probe}=$text; untie %g;
tie %g, 'GDBM_File', 'gdbm-file', GDBM_READER, 0600 or die $!;
die 'GDBM roundtrip' unless $g{probe} eq $text; untie %g;
# Native compression objects must be destroyed before ithreads clones this interpreter.
{
my ($def,$status)=Compress::Raw::Zlib::Deflate->new();die 'deflate init' unless $status==Z_OK;
my ($compressed,$tail,$plain)=('','','');die 'deflate' unless $def->deflate($text,$compressed)==Z_OK;
die 'flush' unless $def->flush($tail)==Z_OK;$compressed.=$tail;
my ($inf,$s)=Compress::Raw::Zlib::Inflate->new();die 'inflate init' unless $s==Z_OK;
die 'inflate' unless $inf->inflate($compressed,$plain)==Z_STREAM_END && $plain eq $text;
my ($bz,$bs)=Compress::Raw::Bzip2->new(1,9,30,0);die 'bzip init' unless $bs==BZ_OK;
my ($bzout,$out)=('','');die 'bzip' unless $bz->bzdeflate($text,$bzout)==BZ_RUN_OK;
die 'bzip close' unless $bz->bzclose($out)==BZ_STREAM_END;$bzout.=$out;
my ($bi,$is)=Compress::Raw::Bunzip2->new(0,0);die 'bunzip init' unless $is==BZ_OK;
my $decoded='';die 'bunzip' unless $bi->bzinflate($bzout,$decoded)==BZ_STREAM_END && $decoded eq $text;
}
my $shared :shared=0;my $t=threads->create(sub { lock($shared);$shared=42;return 17; });
die 'threads' unless $t->join()==17 && $shared==42;
die 'JSON' unless decode_json(encode_json({answer=>42}))->{answer}==42;
die 'SHA' unless sha256_hex('abc') eq 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
print "PERL5423_FUNCTIONAL_OK\nDB_FILE=ROUNDTRIP\nGDBM=ROUNDTRIP\nZLIB=ROUNDTRIP\nBZIP2=ROUNDTRIP\nTHREADS=JOIN_SHARED\nLIBPERL=SHARED\n";
