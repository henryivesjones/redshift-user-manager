import os

from setuptools import setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="redshift-user-manager",
    author="Henry Jones",
    author_email="henryivesjones@gmail.com",
    url="https://github.com/henryivesjones/redshift-user-manager",
    description="A user management CLI tool for AWS Redshift.",
    packages=["redshift_user_manager"],
    package_dir={"redshift_user_manager": "redshift_user_manager"},
    package_data={"redshift_user_manager": ["py.typed"]},
    include_package_data=True,
    long_description=read("README.md"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Utilities",
    ],
)
