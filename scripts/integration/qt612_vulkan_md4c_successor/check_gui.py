#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the bounded Vulkan and external md4c ABI in one QtGui ELF."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess


VULKAN_EXPORTS = frozenset({
    "_ZN20QRhiVulkanInitParams27preferredInstanceExtensionsEv@Qt_6_PRIVATE_API",
    "_ZN22QVulkanDefaultInstance7setFlagENS_4FlagEb@Qt_6_PRIVATE_API",
    "_ZN22QVulkanDefaultInstance8instanceEv@Qt_6_PRIVATE_API",
    "_ZN7QWindow17setVulkanInstanceEP15QVulkanInstance@Qt_6",
    "_ZNK15QVulkanInstance10apiVersionEv@Qt_6",
    "_ZNK7QWindow14vulkanInstanceEv@Qt_6",
})


def check_readback(text):
    symbols = re.findall(r"^\s*\d+:\s+[\da-fA-F]+\s+\d+\s+FUNC\s+GLOBAL\s+DEFAULT\s+(\d+|UND)\s+(\S+)",
                         text, re.MULTILINE)
    exports = {name.replace("@@", "@", 1) for index, name in symbols if index != "UND"}
    missing = VULKAN_EXPORTS - exports
    if missing:
        raise ValueError("missing versioned QtGui Vulkan exports: " + ", ".join(sorted(missing)))
    if (re.findall(r"\(NEEDED\)\s+Shared library: \[(libmd4c[^\]]*)\]", text) != ["libmd4c.so.0"]
            or symbols.count(("UND", "md_parse")) != 1
            or not re.search(r"\bR_(?:AARCH64|X86_64)_(?:JUMP_SLOT|GLOB_DAT)\s+[\da-fA-F]+\s+md_parse\s+\+\s+0\b", text)):
        raise ValueError("QtGui must dynamically relocate md_parse to libmd4c.so.0")
    return dict(vulkan_exports=sorted(VULKAN_EXPORTS), external_md4c_import="md_parse",
                md4c_soname="libmd4c.so.0", scope="ELF_READBACK_ONLY")


def check_file(library):
    result = subprocess.run(["readelf", "--wide", "--dynamic", "--dyn-syms", "--relocs", str(library)],
                            check=True, capture_output=True, text=True, encoding="ascii", timeout=30,
                            env={**os.environ, "LC_ALL": "C"})
    return check_readback(result.stdout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    try:
        print(json.dumps(check_file(parser.parse_args().library), sort_keys=True))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")
