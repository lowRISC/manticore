#!/usr/bin/env python3
# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""
Generates a new message type.
"""

import argparse
import os
import shutil
import subprocess
import sys
import re
from pathlib import Path

SRC_PROTOCOL = Path(__file__).parent
TEMPLATE = SRC_PROTOCOL / "message.rs.tpl"

def eprint(*args):
  "Prints to stderr."
  print(*args, file = sys.stderr)

def camel_to_snake(camel):
  snake = ""
  for c in camel:
    if snake != "" and c.isupper():
      snake += "_"
    snake += c.lower()
  return snake

def main():
  parser = argparse.ArgumentParser(description="Generate a new message type.")
  parser.add_argument("path",
                      metavar="path",
                      help="Name, relative to manticore::protocol, of the new message.")

  options = parser.parse_args()

  components = options.path.split("::")
  filepath = SRC_PROTOCOL / '/'.join(components[:-1]) / (camel_to_snake(components[-1]) + ".rs")

  generated = TEMPLATE.read_text().replace("{command}", components[-1])
  filepath.write_text(generated)
  eprint(f"wrote {filepath}")

if __name__ == '__main__':
  main()
