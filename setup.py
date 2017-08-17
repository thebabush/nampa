from setuptools import setup

setup(name='nampa',
      version='0.1',
      description='FLIRT signatures for python',
      url='https://github.com/kenoph/nampa',
      author='Paolo Montesel',
      license='LGPL',
      packages=['nampa'],
      install_requires=[
          'future',
      ],
      scripts=['dumpsig.py'],
      zip_safe=False)

