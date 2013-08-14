# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

VERSION='0.2'
APPNAME='ndndump'

from waflib import Build, Logs

def options(opt):
    opt.load('compiler_c compiler_cxx boost')
    opt.load('flags ndnx', tooldir=['waf-tools'])
    opt.add_option('--yes',action='store_true',default=False) # for autoconf/automake/make compatibility

def configure(conf):
    conf.load("compiler_c compiler_cxx boost flags ndnx")
    conf.check_cfg(path='pcap-config', package="libpcap", args=['--cflags', '--libs'], uselib_store='PCAP', mandatory=True)

    conf.check_boost(lib='system iostreams regex')

    boost_version = conf.env.BOOST_VERSION.split('_')
    if int(boost_version[0]) < 1 or int(boost_version[1]) < 46:
        Logs.error ("Minumum required boost version is 1.46")
        return

    conf.check_ndnx (path=conf.options.ndnx_dir)
    conf.check_openssl ()

    conf.write_config_header('src/config.h')

def build (bld):
    ndndump = bld (
        target=APPNAME,
        features=['cxx', 'cxxprogram'],
        source = bld.path.ant_glob(['src/**/*.cc']),
        use = 'BOOST BOOST_IOSTREAMS BOOST_REGEX NDNX PCAP',
        includes = ['src/ndnb-parser', 'src/ndnb-parser/ns3', 'src'],
        )
    
