# SPDX-License-Identifier: MIT
project('developer_fixture', 'c', 'cpp', version: '1.0.0',
        default_options: ['warning_level=3', 'werror=true', 'buildtype=debugoptimized'])
library = shared_library('greeting', 'greeting.cpp', install: true)
demo = executable('developer-demo', 'main.c', link_with: library,
                  install: true, install_rpath: '$ORIGIN/../lib')
test('greeting', demo, args: ['--self-test', meson.current_source_dir() / 'expected.txt'])
install_data('LICENSE', install_dir: get_option('datadir') / 'licenses/developer-fixture')
