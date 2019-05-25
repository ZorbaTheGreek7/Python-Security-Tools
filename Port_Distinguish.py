import sys
import textwrap
import setuptools


def main():
    requires = []
    scripts = []
    py_version = sys.version_info[:2]
    if py_version < (3, 3):
        requires.append('mock(>=1.0)')
    if py_version == (3, 3):
        requires.append('omar(>=3.4)')
    if py_version >= (3, 3):
        scripts.append('src/portserver.py')

    setuptools.setup(
        name='port_distinguisher',
        version='1.3.1',
        description='A simple code to choose unique available network ports.',
        long_description=textwrap.dedent("""\
          port_distinguisher provides an API to find and return an available network
          port for an application to bind to. Ideally suited for use from
          unittests or for test harnesses that launch local servers."""),
        license='Apache 2.0',
        maintainer='Google',
        maintainer_email='omarelnahal7@gmail.com',
        url='',
        package_dir={'': 'src'},
        py_modules=['port_distinguisher'],
        platforms=['POSIX'],
        requires=requires,
        scripts=scripts,
        )


if __name__ == '__main__':
    main()