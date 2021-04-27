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
    description=('Generates FromWire/ToWire fuzz targets for a '
                 '`manticore::protocol` message.'))
  subcommands = argparser.add_subparsers(
    required=True,
    dest='subcommand',
    help='subcommands')

  argparser_generate = subcommands.add_parser(
    'generate',
    help='generate new fuzz targets')
  argparser_generate.add_argument(
    'typename',
    type=str,
    help=('the name of the type to fuzz, such as '
          'firmware_version::FirmwareVersionRequest'))
  argparser_generate.add_argument(
    '--fuzz-dir',
    type=str,
    default='fuzz',
    help='the fuzzing directory, relative to the project root')
  argparser_generate.add_argument(
    '--target-templates',
    type=str,
    nargs='*',
    choices=['to_wire', 'from_wire', 'to_wire_fuzz_safe'],
    default=['to_wire', 'from_wire'],
    metavar='TEMPLATE',
    help=('which targets to generate. choices: %(choices)s (default: %(default)s)'))

  argparser_ci = subcommands.add_parser(
      'ci',
      help='generate CI jobs for a set of fuzz targets for one command type')
  argparser_ci.add_argument(
      'message_type',
      type=str,
      help=('prefix for the four fuzz targets to generate a job for, such as '
            'firmware_version'))
  argparser_ci.add_argument(
      '--workflow-file',
      type=str,
      default='.github/workflows/fuzz.yml',
      help='the workflow file, relative to the project root')

  args = argparser.parse_args()

  util_dir = os.path.dirname(__file__)
  repo_top = os.path.dirname(util_dir)
  command = ' '.join(sys.argv)

  if args.subcommand == 'generate':
    fuzz_dir = os.path.join(repo_top, args.fuzz_dir)
    (module, typename) = tuple(args.typename.split('::'))
    typeid = re.match('\w+', typename)[0]  # Remove a trailing <'static>
    snake_case_name = camel_to_snake(typeid)

    renames = {'to_wire_fuzz_safe': 'to_wire'}
    for template_name in args.target_templates:
      template = read_file(os.path.join(
          util_dir, '{}.rs.tpl'.format(template_name)))

      if template_name in renames:
        template_name = renames[template_name]
      name = "{}_{}".format(snake_case_name, template_name)
      src = template.format(module=module, typename=typename,
                            typeid=typeid, command=command)

      add_target(fuzz_dir, name, src)
  elif args.subcommand == 'ci':
    template_path = os.path.join(util_dir, 'fuzz_job.yml.tpl')
    template = read_file(template_path)
    job = template.format(message_type=args.message_type, command=command)

    workflow_file = os.path.join(repo_top, args.workflow_file)
    append_to_file(workflow_file, job)


if __name__ == '__main__':
  main()
