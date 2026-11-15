# SPDX-License-Identifier: MIT
use strict;
use warnings;
use Config;
use Module::CoreList;

die "selected Perl version required\n" unless "$^V" eq 'v5.42.3';
die "source-epoch configure time required\n" unless $Config{cf_time} eq 'Sun Aug  2 00:00:00 UTC 2026';
die "shared threaded Perl required\n"
    unless $Config{useshrplib} eq 'true' && $Config{useithreads} eq 'define';
my %paths = (
    prefix => '/usr', privlib => '/usr/share/perl5/core_perl',
    archlib => '/usr/lib/perl5/5.42/core_perl',
    vendorlib => '/usr/share/perl5/vendor_perl',
    vendorarch => '/usr/lib/perl5/5.42/vendor_perl',
    sitelib => '/usr/local/share/perl5/site_perl',
    sitearch => '/usr/local/lib/perl5/5.42/site_perl',
    scriptdir => '/usr/bin/core_perl',
);
for my $key (sort keys %paths) {
    die "wrong configured $key: $Config{$key}\n" unless $Config{$key} eq $paths{$key};
}
my $core = $Module::CoreList::version{5.042003}
    or die "selected source CoreList5.042003 required\n";
my %aliases = ('db_file' => 'DB_File', 'pathtools' => 'Cwd', 'libnet' => 'Net::FTP', 'podlators' => 'Pod::Man');
my %names;
for my $module (sort keys %$core) {
    (my $name = lc $module) =~ s/::|_/-/g;
    $names{$name} = $module;
}
open my $claims, '<', $ARGV[0] or die "provider facts: $!\n";
my $count = 0;
while (my $line = <$claims>) {
    chomp $line;
    my ($name, $version) = $line =~ /\Aperl-([a-z0-9_-]+)=([0-9._]+)\z/
        or die "nonliteral provider claim\n";
    my $module = $aliases{$name} // $names{$name} // die "unknown core provider $name\n";
    my $actual = $core->{$module};
    # Pod::Man uses a v-string spelling; package versions use the dotted form.
    $actual =~ s/\Av(?=\d+\.\d+\.\d+\z)// if defined $actual;
    die "source version differs for $module: " . ($actual // 'undef') . "\n"
        unless defined $actual && $actual eq $version;
    ++$count;
}
close $claims or die "provider facts close: $!\n";
die "exact113 source-checked providers required\n" unless $count == 113;
# Force actual optional C extensions to load; a configure-time silent omission fails.
for my $module (qw(DB_File GDBM_File Compress::Raw::Zlib Compress::Raw::Bzip2 threads)) {
    (my $file = "$module.pm") =~ s{::}{/}g;
    require $file;
}
print "PASS selected shared threaded Perl5.42.3 paths,113 core providers and five C extensions\n";
