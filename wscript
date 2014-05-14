# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

VERSION='0.5'
APPNAME='ndndump'

from waflib import Build, Logs

ATTRIBUTE_CHECK='''
#include <stdlib.h>

static void foo(void) __attribute__ ((noreturn));

static void
foo(void)
{
  exit(1);
}

int
main(int argc, char** argv)
{
  foo();
}
'''


def options(opt):
    opt.load(['compiler_cxx'])
    opt.load(['default-compiler-flags', 'boost'], tooldir=['.waf-tools'])

def configure(conf):
    conf.load("compiler_cxx boost default-compiler-flags")

    conf.check(header_name="inttypes.h", mandatory=False)
    conf.check(header_name="stdint.h", mandatory=False)
    conf.check(header_name="sys/bitypes.h", mandatory=False)
    conf.check(fragment=ATTRIBUTE_CHECK, msg="Checking for __attribute__", mandatory=False)

    conf.check(header_name=["sys/types.h", "sys/time.h", "time.h"], define="TIME_WITH_SYS_TIME",
               mandatory=False)

    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'],
                   uselib_store='NDN_CXX', mandatory=True)

    conf.check_cfg(path='pcap-config',
                   package="libpcap", args=['--libs', '--cflags'],
                   uselib_store='PCAP', mandatory=True)

    conf.check_boost(lib='system iostreams regex')

    conf.write_config_header('src/config.hpp')

def build (bld):
    ndndump = bld(
        target='ndndump',
        features=['cxx', 'cxxprogram'],
        source=bld.path.ant_glob(['src/**/*.cpp']),
        use='NDN_CXX BOOST PCAP',
        includes="src",
        )
