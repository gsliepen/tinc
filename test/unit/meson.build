dep_cmocka = dependency('cmocka', required: opt_tests)
if not dep_cmocka.found()
  subdir_done()
endif

can_wrap = cc.has_link_argument('-Wl,--wrap=func')
if not can_wrap
  message('linker has no support for function wrapping, mocked tests will not run')
endif

link_tinc = { 'lib': lib_tinc, 'dep': deps_tinc }
link_tincd = { 'lib': lib_tincd, 'dep': deps_tincd }

# Test definition format:
#
# 'free-form test name': {
#   'code': 'test1.c',      // or ['test1.c', 'test1_util.c']
#   'mock': ['foo', 'bar'], // list of functions to mock (default: empty)
#   'link': link_tinc,      // which binary to link with (default: tincd)
#   'fail': true,           // whether the test should fail (default: false)
#   'cases': ['foo'],       // run once per case, passing it as argument (default: once)
# }

tests = {
  'dropin': {
    'code': 'test_dropin.c',
  },
  'random': {
    'code': 'test_random.c',
  },
  'random_noinit': {
    'code': 'test_random_noinit.c',
    'fail': true,
  },
  'graph': {
    'code': 'test_graph.c',
  },
  'netutl': {
    'code': 'test_netutl.c',
  },
  'net': {
    'code': 'test_net.c',
    'mock': ['execute_script', 'environment_init', 'environment_exit'],
  },
  'subnet': {
    'code': 'test_subnet.c',
  },
  'protocol': {
    'code': 'test_protocol.c',
  },
  'proxy': {
    'code': 'test_proxy.c',
  },
  'utils': {
    'code': 'test_utils.c',
  },
  'fs': {
    'code': 'test_fs.c',
  },
  'xalloc': {
    'code': 'test_xalloc.c',
  },
  'memzero_null': {
    'code': 'test_memzero_null.c',
    'fail': true,
  },
  'splay_tree': {
    'code': 'test_splay_tree.c',
    'link': link_tinc,
  },
}

if can_wrap
  tests += {
    'address_cache': {
      'code': ['test_address_cache.c', 'fake_getaddrinfo.c'],
      'mock': ['getaddrinfo', 'retry_outgoing_now'],
      'cases': [
        'test_numeric_addresses_need_no_waiting',
        'test_lookups_run_in_parallel',
        'test_order_of_address_statements_is_kept',
        'test_failed_lookups_are_skipped',
        'test_lookup_completing_during_connection_attempt_does_not_wake',
        'test_reset_cancels_pending_lookups',
        'test_any_address_statements',
      ],
    },
    'resolver': {
      'code': ['test_resolver.c', 'fake_getaddrinfo.c'],
      'mock': ['getaddrinfo'],
      'cases': [
        'test_resolve_numeric',
        'test_resolve_calls_back_later',
        'test_resolve_failure',
        'test_slow_lookup_does_not_block_event_loop',
        'test_cancelled_lookup_does_not_call_back',
        'test_concurrent_lookups',
      ],
    },
  }
endif

env = ['CMOCKA_MESSAGE_OUTPUT=TAP']

foreach test, data : tests
  args = ld_flags

  if can_wrap
    mocks = data.get('mock', [])
    if mocks.length() > 0
      args += ',--wrap='.join(['-Wl'] + mocks)
    endif
  endif

  libs = data.get('link', link_tincd)

  exe = executable(test,
                   sources: data['code'],
                   link_args: args,
                   dependencies: [libs['dep'], dep_cmocka],
                   link_with: libs['lib'],
                   implicit_include_directories: false,
                   include_directories: inc_conf,
                   build_by_default: false)

  must_fail = data.get('fail', false)

  foreach case : data.get('cases', [''])
    test(case == '' ? test : test + ':' + case,
         exe,
         args: case == '' ? [] : [case],
         suite: 'unit',
         timeout: 60,
         protocol: must_fail ? 'exitcode' : 'tap',
         env: env,
         should_fail: must_fail)
  endforeach
endforeach

