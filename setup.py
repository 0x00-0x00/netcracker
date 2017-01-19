from setuptools import setup, find_packages

setup(name='netcracker',
      version='0.1.4',
      description='A wireless network scanner and automated cracker.',
      url='https://bitbucket.org/itslikeme/netcracker',
      author='Shemhazai',
      author_email='nestorm2486@gmail.com',
      license='MIT',
      packages=['netcracker'],
      package_dir={"netcracker": "src"},
      package_data={"netcracker": ["src/*"]},
      scripts=['bin/netcracker'],
      zip_safe=False)
