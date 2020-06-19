#!/usr/bin/env python3
# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""
Creates a new fuzz target for a given `manticore::protocol` message.

This script exists to minimize the boilerplate of doing so, seeing as such
targets tend to be quite simple.
"""

import argparse
import os
import sys
import re


def camel_to_snake(camel):
  """
  Convert `camel` to snake case.
  """
  return ''.join(['_' + c.lower() if c.isupper() else c for c in camel]).strip('_')

def read_file(filename):
  """
  Fully reads a file into a UTF-8 string.
  """
  with open(filename, 'r') as f:
    return f.read()

def append_to_file(filename, text):
  """
  Open or create `filename` and append `text` to it.
  """
  with open(filename, 'a') as f:
    f.write(text)

def add_target(fuzz_dir, name, rs_src):
  """
  Add a fuzz target named `name` with the given source file to the fuzzing
  directory `fuzz_dir`.

  If `name.rs` is present, the target is assumed to already be present.
  """
  target_rs = os.path.join(fuzz_dir, 'fuzz_targets', '{}.rs'.format(name))
  if os.path.exists(target_rs):
    return
  append_to_file(target_rs, rs_src)

  cargo_toml = os.path.join(fuzz_dir, 'Cargo.toml')
  append_to_file(cargo_toml,
"""
[[bin]]
name = "{target}"
path = "fuzz_targets/{target}.rs"
""".format(target=name))

def main():
  argparser = argparse.ArgumentParser(
    description=
    'Generates Deserialize/Serialize fuzz targets for a `manticore::protocol` '\
    'message.\n The type name of the message should be provided relative to '\
    '`manticore::protocol`.'
  )
  argparser.add_argument('typename',
                         type=str,
                         help='the name of the type to fuzz, such as '\
                              'firmware_version::FirmwareVersionRequest')
  argparser.add_argument('--target-templates',
                         type=str,
                         choices=['serialize', 'deserialize'],
                         nargs='*',
                         default=['serialize', 'deserialize'],
                         help='which target templates to use; defaults to all')
  argparser.add_argument('--fuzz-dir',
                         type=str,
                         default='fuzz',
                         help='the fuzzing directory, relative to the project'\
                              'root')
  args = argparser.parse_args()

  util_dir = os.path.dirname(__file__)
  fuzz_dir = os.path.join(os.path.dirname(util_dir), args.fuzz_dir)
  (module, typename) = tuple(args.typename.split('::'))
  typeid = re.search('^\w+', typename)[0]  # Remove a trailing <'static>
  snake_case_name = camel_to_snake(typeid)
  command = ' '.join(sys.argv)

  for template_name in args.target_templates:
    template = read_file(os.path.join(
        util_dir, '{}.rs.template'.format(template_name)))

    name = "{}_{}".format(snake_case_name, template_name)
    src = template.format(module=module, typename=typename,
                          typeid=typeid, command=command)

    add_target(fuzz_dir, name, src)

if __name__ == '__main__':
  main()
