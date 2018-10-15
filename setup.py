from setuptools import setup, find_packages

setup(name='aci_gw_migrator',
      version='0.1',
      description='Legacy to ACI GW Migrator Tool',
      url='',
      author='Carl Niger',
      author_email='carlniger@gmail.com',
      license='',
      packages=find_packages(),
      install_requires=['netmiko',
                        'pandas',
                        'requests',
                        'acipdt'],
      dependency_links=['git+git://github.com/carlniger/acipdt@master#egg=acipdt'])
