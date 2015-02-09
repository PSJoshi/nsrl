from setuptools import setup,find_packages

requires = ['argparse','configparser','hashlib>=20081119','requests','urlparse2>=1.1','peewee>=2.4']

setup(name='malware_inspector',
      version='0.1',
      description='md5/sha-1 hash based malware checker using NSRL,Team Cymru and Virustotal hash registry ',
      long_description=("""
      This program computes md5/sha-1 hashes of directories and removes good hashes using National Software
      Reference Library. The remaining hashes are checked against Team Cymru and VirusTotal Hash registry. The suspicious
      hashes along with the files are reported in file/e-mail to the user for further investigations.The use of celery
      - a python based distributed queue is made while checking hashes against Team Cymru/Virustotal hash registry services.
      """),
      url='',
      author='Pradyumna Joshi',
      author_email='joshi.pradyumna@gmail.com',
      license='Apache',
      keywords='malware,hash',
      install_requires=requires,
      platforms='any',
      packages=find_packages(),
      # package_data={
      #       '': ['*.conf', '*.rst', '*.txt'],
      #  },
      data_files=[('./etc/malware_inspector/',['hash_check/conf/hash.conf'])],
      entry_points={
        'console_scripts': ['celery_malware_check=hash_checker.hash_check:main',
        ]
      },
      include_package_data=True,
      classifiers=[
        "Programming Language :: Python",
        "Topic :: Security :: Malware",
        "Development Status :: 2 - Pre-Alpha",
        'Natural Language :: English',
        ],
      zip_safe=False)
