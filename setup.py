import sys
import os
import re
import platform
import subprocess
import fnmatch

from setuptools import Extension, setup, find_packages
from setuptools.command.build_ext import build_ext
from setuptools.command.install_lib import install_lib as install_lib_orig
from packaging.version import Version


if sys.version_info < (3, 11):
    sys.exit('Python < 3.11 is not supported')

exclude = ['*-obj*', 'tools']

# dirty hack to allow excluding files other than .py while using bdist_wheel
class install_lib(install_lib_orig):
    def install(self):
        outputs = super().install()
        new_outputs = []
        for o in outputs:
            if not any(fnmatch.fnmatch(o, pattern) for pattern in exclude):
                new_outputs.append(o)
            if any(fnmatch.fnmatch(o, pattern) for pattern in exclude):
                print(f"Removing file from build: {o}")
                os.remove(o)
        return new_outputs


class CMakeExtension(Extension):
    def __init__(self, name, sourcedir=''):
        Extension.__init__(self, name, sources=[])
        self.sourcedir = os.path.abspath(sourcedir)


class CMakeBuild(build_ext):
    def run(self):
        try:
            out = subprocess.check_output(['cmake', '--version'])
        except OSError:
            raise RuntimeError("CMake must be installed to build the following extensions: " +
                               ", ".join(e.name for e in self.extensions))

        if platform.system() == "Windows":
            cmake_version = Version(re.search(r'version\s*([\d.]+)', out.decode()).group(1))
            if cmake_version < Version('3.15.0'):
                raise RuntimeError("CMake >= 3.15.0 is required on Windows")

        for ext in self.extensions:
            self.build_extension(ext)

    def build_extension(self, ext):
        extdir = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))
        # required for auto-detection of auxiliary "native" libs
        if not extdir.endswith(os.path.sep):
            extdir += os.path.sep

        cmake_args = ['-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=' + extdir,
                      '-DPYTHON_EXECUTABLE=' + sys.executable]

        # cfg = 'Debug' if self.debug else 'Release'
        cfg = 'Release'
        build_args = ['--config', cfg]

        if platform.system() == "Windows":
            cmake_args += ['-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{}={}'.format(cfg.upper(), extdir)]
            if sys.maxsize > 2**32:
                cmake_args += ['-A', 'x64']
            build_args += ['--', '/m']
        else:
            cmake_args += ['-DCMAKE_BUILD_TYPE=' + cfg]
            build_args += ['--', '-j2']
            if sys.platform.startswith("darwin"):
                # Cross-compile support for macOS - respect ARCHFLAGS if set
                archs = re.findall(r"-arch (\S+)", os.environ.get("ARCHFLAGS", ""))
                if archs:
                    cmake_args += ["-DCMAKE_OSX_ARCHITECTURES={}".format(";".join(archs))]

        env = os.environ.copy()
        env['CXXFLAGS'] = '{} -DVERSION_INFO=\\"{}\\"'.format(env.get('CXXFLAGS', ''),
                                                              self.distribution.get_version())
        if not os.path.exists(self.build_temp):
            os.makedirs(self.build_temp)
        subprocess.check_call(['cmake', ext.sourcedir] + cmake_args, cwd=self.build_temp, env=env)
        subprocess.check_call(['cmake', '--build', '.'] + build_args, cwd=self.build_temp)


with open('README.rst') as readme_file:
    readme = readme_file.read()

setup(
    author='Erik van den Brink',
    author_email='erik@coz.io',
    name='neo3crypto',
    python_requires='>=3.12.0,<3.14',
    description="Native crypto functions for the NEO 3 Blockchain",
    long_description=readme,
    long_description_content_type="text/x-rst",
    version='0.4.4',
    license='MIT',
    url='https://github.com/CityOfZion/neo3crypto',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        "Programming Language :: C++"
    ],
    ext_modules=[CMakeExtension('neo3crypto')],
    cmdclass={'build_ext': CMakeBuild, 'install_lib': install_lib},
    packages=find_packages(),
)
