from setuptools import setup,find_packages
import os

requires = ['argparse','configparser','hashlib>=20081119','requests','urlparse2>=1.1','peewee>=2.4']
#cur_dir=os.path.dirname(__file__)
#conf_file = os.path.join(os.path.sep,os.path.dirname(os.path.realpath(__file__)),'hash_checker/*.conf')

setup(name='malware_inspector',
      version='0.1',
      description='Malware checker using NSRL (NIST) hash database,Team Cymru and Virustotal hash registry ',
      long_description=("""
      This program computes md5/sha-1 hashes of directorie(s) and removes good hashes using National Software
      Reference Library. The remaining hashes are checked against Team Cymru and VirusTotal Hash registry. The suspicious
      hashes along with the files are reported in file/e-mail to the user for further investigations.
      """),
      url='',
      author='Pradyumna Joshi',
      author_email='joshi.pradyumna@gmail.com',
      license='Apache',
      keywords='malware,hash',
      install_requires=requires,
      platforms='any',
      packages=find_packages(),
      data_files = [('./etc/malware_inspector/',['hash_checker/conf/hash.conf']),], 
      # package_data={
      #       '': ['*.conf', '*.rst', '*.txt'],
      #  },
      #package_data={'hash_checker': ['/etc/malware_inspector/','conf/*.conf']},
      
      entry_points={
        'console_scripts': ['malware_check=hash_checker.hash_check:main',
        ]
      },
      #include_package_data=True,
      classifiers=[
        "Programming Language :: Python",
        "Topic :: Security :: Malware",
        "Development Status :: 2 - Pre-Alpha",
        'Natural Language :: English',
        ],
      zip_safe=False)
