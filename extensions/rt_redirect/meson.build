shared_module('rt_redirect',
    sources : [files(
      'rt_redir.h',
      'rt_redir.c',
      'redir_entries.c',
      'redir_expiry.c',
      'redir_fwd.c',
      'redir_out.c',
      'uthash.h'
    )],
    include_directories : freeDiameter_includes,
    dependencies : libfdcore_dep,
    name_prefix : '',
    name_suffix : 'fdx',
    install : true,
    install_dir : freeDiameter_extensionsdir)