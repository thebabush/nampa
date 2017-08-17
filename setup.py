from setuptools import setup

setup(name='nampa',
      version='0.1.0',
      description='FLIRT signatures for python',
      url='https://github.com/kenoph/nampa',
      author='Paolo Montesel',
      license='LGPL',
      packages=['nampa'],
      install_requires=[
          'future',
      ],
      scripts=['dumpsig.py'],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 3',
      ],
      zip_safe=False)

