conf_data = configuration_data()
if cc.has_header_symbol('regex.h', 'REG_STARTEND')
  conf_data.set('HAVE_REG_STARTEND', 1)
endif
configure_file(output : 'rt_default-host.h',
                configuration : conf_data)


lgen = generator(flex,
    output : 'lex.@BASENAME@.c',
    arguments : ['-p', '-Cem', '-Prtd_conf', '-o', '@OUTPUT@', '@INPUT@']
    )
lfiles = lgen.process('rtd_conf.l')

pgen = generator(bison,
    output : ['@BASENAME@.tab.c', '@BASENAME@.tab.h'],
    arguments : ['-p', 'rtd_conf', '-d',
                 '@INPUT@', '--defines=@OUTPUT1@', '--output=@OUTPUT0@'])
pfiles = pgen.process('rtd_conf.y')

# List of source files
rt_default_src = files(
	'rt_default.c',
	'rt_default.h',
	'rtd_rules.c',
)

shared_module('rt_default',
    sources : [rt_default_src, lfiles, pfiles],
    include_directories : freeDiameter_includes,
    dependencies : libfdcore_dep,
    name_prefix : '',
    name_suffix : 'fdx',
    install : true,
    install_dir : freeDiameter_extensionsdir)
