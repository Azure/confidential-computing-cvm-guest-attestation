# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import ctypes
import os
from enum import IntFlag
from typing import Optional, Tuple, Union

# Import the low-level bindings
from .bindings import unprotect_secret as _unprotect_secret
from .bindings import free_secret as _free_secret
from .bindings import is_cvm as _is_cvm

# Policy options directly mirroring the C++ code
class PolicyOption(IntFlag):
    """Policy options controlling security requirements for secret access."""
    RequireAll = 0b00000000
    AllowUnencrypted = 0b00000001
    AllowUnsigned = 0b00000010
    AllowLegacy = 0b00000100
    
    # Common combinations
    AllowAny = AllowUnencrypted | AllowUnsigned | AllowLegacy

# Evaluated features directly mirroring the C++ code
class PayloadFeature(IntFlag):
    """Policy options controlling security requirements for secret access."""
    NoSettings = 0b00000000
    Encrypted  = 0b00000001
    Signed     = 0b00000010
    Legacy     = 0b00000100

class SecretException(Exception):
    """Exception raised when a secret operation fails."""
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"Secret operation failed with code {code}: {message}")

def unprotect_secret(jwt: Union[str, bytes], 
                    policy: Union[int, PolicyOption] = PolicyOption.AllowUnsigned) -> Tuple[bytes, PayloadFeature]:
    """
    Unprotect a secret using the JWT token.
    
    Args:
        jwt: The JWT token as a string or bytes
        policy: Policy options controlling security requirements
    
    Returns:
        Tuple of (secret_bytes, eval_policy_flags)
    
    Raises:
        SecretException: If the secret cannot be unprotected
    """
    # Convert string to bytes if needed
    if isinstance(jwt, str):
        jwt = jwt.encode('utf-8')
    
    # Prepare output parameters
    output_secret = ctypes.POINTER(ctypes.c_char)()
    eval_policy = ctypes.c_uint(0)
    
    # Call the C function
    result = _unprotect_secret(
        jwt, 
        len(jwt), 
        ctypes.c_uint(int(policy)), 
        ctypes.byref(output_secret), 
        ctypes.byref(eval_policy)
    )
    
    # Check for errors
    if result < 0:
        raise SecretException(result, f"Failed to unprotect secret (code {result})")
    
    # Copy the secret to a Python bytes object
    secret_bytes = bytes(output_secret[:result])
    
    # Free the memory allocated by the C function
    _free_secret(output_secret)
    
    return secret_bytes, eval_policy.value

def is_cvm() -> bool:
    """
    Check if the current machine is a Confidential VM.
    
    Returns:
        True if running on a Confidential VM, False otherwise
    """
    return bool(_is_cvm())