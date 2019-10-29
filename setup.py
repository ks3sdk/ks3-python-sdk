try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

with open('README.md', 'rb') as f:
    readme = f.read().decode('utf-8')

setup(
    name='ks3sdk',
    version='1.0.14',
    description='Kingsoft Standard Storage Service SDK',
    long_description=readme,
    long_description_content_type='text/markdown',
    packages=['ks3'],
    install_requires=[
        'six'
    ],
    include_package_data=True,
    url='https://github.com/ks3sdk/ks3-python-sdk',
    author='ksc_ks3',
    author_email='ksc_ks3@kingsoft.com',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.7'
    ]
)
