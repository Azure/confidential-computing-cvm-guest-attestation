# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# DynamicSecretsProvisioningLibrary/python/setup.py
from setuptools import setup, find_packages

setup(
    name="python3-azure-protected-vm-secrets",
    version="0.1.0",
    description="Python bindings for Azure Protected VM Secrets",
    author="Microsoft Corporation",
    packages=find_packages(),
    python_requires='>=3.6',
    license="MIT",
)