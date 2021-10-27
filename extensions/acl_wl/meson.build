lgen = generator(flex,
    output : 'lex.@BASENAME@.c',
    arguments : ['-p', '-Cem', '-Paw_conf', '-o', '@OUTPUT@', '@INPUT@'])
lfiles = lgen.process('aw_conf.l')

pgen = generator(bison,
    output : ['@BASENAME@.tab.c', '@BASENAME@.tab.h'],
    arguments : ['-p', 'aw_conf', '-d',
                 '@INPUT@', '--defines=@OUTPUT1@', '--output=@OUTPUT0@'])
pfiles = pgen.process('aw_conf.y')

shared_module('acl_wl',
    sources : [lfiles, pfiles, files(
      'acl_wl.c',
      'aw_tree.c')],
    include_directories : freeDiameter_includes,
    dependencies : libfdcore_dep,
    name_prefix : '',
    name_suffix : 'fdx',
    install : true,
    install_dir : freeDiameter_extensionsdir)
