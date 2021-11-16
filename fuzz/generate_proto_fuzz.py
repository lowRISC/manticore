#!/usr/bin/env python3
# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""
Regenerates fuzz tests for boilerplate protocol tests by looking at the
`proto_fuzz.txt` file, which is a file containing newline-delimited Rust
paths, which refer to implementations of `manticore::protocol::Command`.

This script exists to minimize the boilerplate of doing so, seeing as such
targets tend to be quite simple.
"""

import argparse
import os
import shutil
import subprocess
import sys
import re
from pathlib import Path

REPO_TOP = Path(__file__).parent.parent

FUZZ_DIR = REPO_TOP / 'fuzz'
FUZZ_CONFIG = FUZZ_DIR / 'proto_types.txt'
FUZZ_TEMPLATES = FUZZ_DIR / 'templates'
FUZZ_GEN = FUZZ_DIR / 'gen'

FUZZ_CARGO = FUZZ_DIR / 'Cargo.toml'
CARGO_TPL = FUZZ_TEMPLATES / 'target.toml.tpl'
CARGO_END = '## BEGIN GENERATED TARGETS'

FUZZ_YML = REPO_TOP / '.github/workflows/fuzz.yml'
YML_TPL = FUZZ_TEMPLATES / 'fuzz_job.yml.tpl'
YML_END = '  ## BEGIN GENERATED JOBS'

def eprint(*args):
  "Prints to stderr."
  print(*args, file = sys.stderr)

def cargo_fuzz_build():
  out = subprocess.run(
      ['cargo', '--quiet', 'fuzz', 'build'],
      cwd = str(FUZZ_DIR))
  eprint()
  eprint(f'Cargo exited with {out.returncode}')
  if out.returncode != 0:
    eprint(f'Fuzz build failed!')
    sys.exit(out.returncode)

def reset_generated_config(path, delim):
  text = path.read_text()
  return text[:text.index(delim)] + delim + '\n'

def main(argv):
  eprint(f'Regenerating {FUZZ_GEN}')
  if not FUZZ_GEN.exists():
    FUZZ_GEN.mkdir()

  cargo_toml = reset_generated_config(FUZZ_CARGO, CARGO_END)
  cargo_tpl = CARGO_TPL.read_text()

  fuzz_yml = reset_generated_config(FUZZ_YML, YML_END)
  yml_tpl = YML_TPL.read_text()

  generated_files = set()
  count = 0
  for ty in FUZZ_CONFIG.read_text().split('\n'):
    if not ty or ty.startswith('#'):
      continue
    eprint(f'Generating tests for {ty}...')

    for tpl in FUZZ_TEMPLATES.iterdir():
      test_type = Path(Path(tpl.stem).name)
      if test_type.suffix != '.rs':
        continue

      under_ty = ty.replace('::', '_')
      path = FUZZ_GEN / f'{under_ty}__{test_type}'
      body = tpl.read_text().format(ty=ty)
      generated_files.add(path)

      relative = path.relative_to(FUZZ_DIR)
      target = f'{under_ty}__{test_type.stem}'
      cargo_toml += cargo_tpl.format(target=target, relative=relative)
      fuzz_yml += yml_tpl.format(target=target, ty=ty, test_type=test_type)
 
      if not path.exists() or path.read_text() != body:
        eprint(f'  * {test_type}.tpl -> {relative}')
        path.write_text(body)
        count += 1
      else:
        eprint(f'  * (skipped) {test_type}.tpl -> {relative}')
  
  eprint(f'Deleting unrecognized files in {FUZZ_GEN}...')
  for file in FUZZ_GEN.iterdir():
    if file not in generated_files:
      eprint(f'  * {file}')
      file.unlink()

  eprint(f'Updating {FUZZ_CARGO}...')
  FUZZ_CARGO.write_text(cargo_toml)
  eprint(f'  * cargo +nighly fuzz build')
  cargo_fuzz_build()

  eprint(f'Updating CI job...')
  FUZZ_YML.write_text(fuzz_yml)
  eprint(f'Generated {count} fuzz tests.')

if __name__ == '__main__':
  main(sys.argv)
