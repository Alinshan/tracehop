from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="tracehop",
    version="3.1.0",
    description="Tracehop - Premium JS Recon & Secret Scanner",
    author="Alinshan",
    license="MIT",
    packages=find_packages(),
    py_modules=["tracehop"],
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'tracehop = tracehop:cli',
            'meow = tracehop:cli',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
