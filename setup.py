from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="tracehop",
    version="2.0.0",
    description="Tracehop - Premium JS Recon & Secret Scanner",
    author="Alinshan",
    packages=find_packages(),
    py_modules=["tracehop"],
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'tracehop = tracehop:cli',
            'meow = tracehop:cli',
        ],
    },
)
