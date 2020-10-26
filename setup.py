from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

version = {}
with open("pac/version.py") as fp:
    exec(fp.read(), version)

setup(
    name="pac",
    version=version['__version__'],
    # url="https://github.com/pietrogiuffrida/carbonium/",
    author="Pietro Giuffrida",
    author_email="pietro.giuffri@gmail.com",
    license="MIT",
    packages=["pac"],
    zip_safe=False,
    install_requires=['requests', 'munch'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    description="AWS CLI shortcuts for EC2",
    long_description=long_description,
    long_description_content_type="text/markdown",
)
