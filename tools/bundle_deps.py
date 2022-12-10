#!/usr/bin/python3

import os
import sys
import glob
import shutil
import subprocess

def ldd_parser(binary):
    res = subprocess.run(['ldd', binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return [dep for dep in map(lambda x: x.split()[2] if len(x.split()) > 3 else None, res.stdout.decode("utf-8").strip().split("\n")) if dep]

def otool_parser(binary):
    res = subprocess.run(['otool', '-L', binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return [dep for dep in map(lambda x: x.split()[0] if '.dylib' in x else None, res.stdout.decode("utf-8").strip().split("\n")[1:]) if dep]

if len(sys.argv) != 3:
    print("Usage: bundle_deps.py node_module output_path")
    exit(1)

module = sys.argv[1]
output_path = sys.argv[2]

deps_parser = None
if sys.platform == "linux":
    deps_parser = ldd_parser
elif sys.platform == "darwin":
    deps_parser = otool_parser
else:
    print(f"Unsupported platform: {sys.platform}")
    exit(1)

all_deps = set()
ignore_deps = set()
modules_deps = {}

def process_bin(binary):
    libs = deps_parser(binary)
    parent_path = os.path.dirname(binary)
    binary_name = os.path.basename(binary)
    modules_deps[binary_name] = []

    for lib in libs:
        modules_deps[binary_name].append(lib)

        if not lib in all_deps:
            lib = lib.replace("@loader_path", parent_path)
            all_deps.add(lib)

            #print(binary + " -> " + lib)
            process_bin(lib)

print(f"bundle {module} dependencies")
process_bin(module)

os.makedirs(output_path, exist_ok=True)

if sys.platform == "darwin":
    # the .dylib files cannot be overwritten, must be deleted
    for f in glob.glob(output_path + "/*.dylib"):
        os.remove(f)

for dep in all_deps:
    libname = os.path.basename(dep)

    if not os.path.exists(dep):
        print(f"  - ignore {dep}")
        ignore_deps.add(libname)
        continue

    print(f"  + {dep}")
    shutil.copy2(dep, output_path)

    if sys.platform == "darwin":
        # Changing a library path into a module requires two steps:
        #   1. change the library id (install_name_tool -id)
        #   2. change the library path in the module (install_name_tool -change)
        # See:
        #   https://stackoverflow.com/questions/66268814/dyld-library-not-loaded-how-to-correctly-tell-gcc-compiler-where-to-find/66284977#66284977
        #   https://developer.apple.com/documentation/xcode/embedding-nonstandard-code-structures-in-a-bundle
        # NOTE: the code signatures of the libs are invalidated by this operation

        #subprocess.run(['codesign', '--remove-signature', output_path + '/' + libname])
        subprocess.run(['install_name_tool', '-id', '@rpath/' + libname, output_path + '/' + libname])

shutil.copy2(module, output_path)

if sys.platform == "darwin":
    print(f"fix dependencies paths")

    for mod, deps in modules_deps.items():
        print(f"  + {mod}")

        for dep in deps:
            libname = os.path.basename(dep)
            if not libname in ignore_deps:
                subprocess.run(['install_name_tool', '-change', dep, '@rpath/' + libname, output_path + '/' + mod])
