configure_file(output: 'config.h', configuration: cdata)

src_lib_common += vcs_tag(
  command: './git_tag.sh',
  fallback: 'unknown',
  input: '../version_git.h.in',
  output: 'version_git.h',
)

