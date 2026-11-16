#!/usr/bin/env python
"""Build jni/libmoderntls.so (mbedTLS + JNI bridge) for armeabi-v7a, Android 2.3.

Uses only the NDK r10e GCC 4.9 toolchain and the android-9 platform; no
ndk-build or make needed. Output: <out>/lib/armeabi-v7a/libmoderntls.so
"""
import argparse, concurrent.futures, hashlib, os, pathlib, subprocess, sys

FLAGS = ['-march=armv7-a', '-mfloat-abi=softfp', '-mfpu=vfpv3-d16', '-marm',
         '-O2', '-fPIC', '-std=gnu99', '-fvisibility=hidden',
         '-ffunction-sections', '-fdata-sections', '-fno-strict-aliasing',
         '-Wall', '-Wno-unused-function', '-DANDROID']


def build(ndk, out):
    ndk, out = pathlib.Path(ndk), pathlib.Path(out)
    jni = pathlib.Path(__file__).resolve().parent
    mbed = jni.parent / 'third_party' / 'mbedtls'
    if (ndk / 'RELEASE.TXT').read_text().split()[0] != 'r10e':
        raise SystemExit('NDK r10e required')
    host = 'windows-x86_64' if os.name == 'nt' else 'linux-x86_64'
    sfx = '.exe' if os.name == 'nt' else ''
    bindir = ndk / 'toolchains/arm-linux-androideabi-4.9/prebuilt' / host / 'bin'
    gcc, strip = bindir / ('arm-linux-androideabi-gcc' + sfx), bindir / ('arm-linux-androideabi-strip' + sfx)
    sysroot = '--sysroot=' + str(ndk / 'platforms/android-9/arch-arm')
    objdir = out / 'obj'
    objdir.mkdir(parents=True, exist_ok=True)
    sources = [jni / 'moderntls.c'] + sorted((mbed / 'library').glob('*.c'))
    inc = ['-include', str(jni / 'mbedtls_pre.h'), '-I', str(jni),
           '-I', str(mbed / 'include'), '-I', str(mbed / 'library')]

    def cc(src):
        obj = objdir / (src.stem + '.o')
        r = subprocess.run([str(gcc), sysroot, *FLAGS, *inc, '-c', str(src), '-o', str(obj)],
                           capture_output=True, text=True)
        return src.name, r.returncode, r.stderr, obj

    objs, failed = [], False
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as ex:
        for name, rc, err, obj in ex.map(cc, sources):
            if err.strip():
                print('--', name, '\n' + err.strip(), file=sys.stderr)
            failed |= rc != 0
            objs.append(obj)
    if failed:
        raise SystemExit('native compile failed')
    lib = out / 'lib' / 'armeabi-v7a' / 'libmoderntls.so'
    lib.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(gcc), sysroot, '-shared', '-Wl,-soname,libmoderntls.so',
                    '-Wl,--gc-sections', '-Wl,--no-undefined', '-Wl,-z,noexecstack',
                    '-Wl,--build-id=none', '-march=armv7-a', '-Wl,--fix-cortex-a8',
                    '-o', str(lib), *[str(o) for o in objs], '-llog', '-lc', '-lm'], check=True)
    subprocess.run([str(strip), '--strip-unneeded', str(lib)], check=True)
    print('native:', lib, lib.stat().st_size, 'bytes, SHA256', hashlib.sha256(lib.read_bytes()).hexdigest())
    return out / 'lib'


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ndk', required=True)
    p.add_argument('--out', required=True)
    a = p.parse_args()
    build(a.ndk, a.out)
