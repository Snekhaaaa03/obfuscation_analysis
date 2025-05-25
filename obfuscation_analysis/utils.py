from __future__ import annotations

import traceback
from typing import Iterable, Optional

from binaryninja.binaryview import BinaryView
from binaryninja.function import Function
from binaryninja.log import log_debug, log_error
from binaryninja.lowlevelil import LowLevelILOperation


def find_corrupted_functions(bv: BinaryView) -> Iterable[Function]:
    """
    Internal generator yielding every function whose disassembly is deemed
    corrupted.

    Parameters
    ----------
    bv : BinaryView
        Active BinaryView to inspect.

    Yields
    ------
    Function
        Each function that appears to contain undefined or overlapping
        instructions.
    """
    for func in bv.functions:
        if has_undefined_instructions(func):
            yield func


def has_undefined_instructions(func: Function) -> bool:
    """
    Return **True** if *func* appears to have *broken* disassembly.

    A function is flagged when **any** of the following hold:

    1. In LLIL form the basic block’s terminator is `LLIL_UNDEF`.
    2. In linear disassembly view a basic block is either
       * empty,
       * marked by Binary Ninja as `has_invalid_instructions`,
         **or**  
       * ends with an instruction that renders as ``"??"``.

    These conditions catch the most common artefacts produced by badly
    obfuscated or partially decoded functions.

    Parameters
    ----------
    func : Function
        Binary Ninja function object to test.

    Returns
    -------
    bool
        ``True`` if the function looks corrupted, ``False`` otherwise.
    """
    # LLIL checks
    if func.llil_if_available is not None:
        # basic block has no instructions or contains the LLIL_UNDEF operation
        for bb in func.llil_if_available.basic_blocks:
            if len(bb) == 0:
                return True
            if bb[-1].operation is LowLevelILOperation.LLIL_UNDEF:
                return True

    # disassembly checks
    for bb in func.basic_blocks:
        # basic block is empty or has invalid instructions
        if bb.has_invalid_instructions or len(bb) == 0:
            return True
        try:
            # final mnemonic string for the last instruction is "??"
            if bb[-1][0][0] == "??":
                return True
        except Exception:
            return True

    return False


def log_stacktrace(prefix: Optional[str] = None) -> None:
    """
    Push the current exception’s traceback to Binary Ninja’s *Debug* log.

    Call this inside an `except` block after the exception object has
    been caught (so that `traceback` can access the active exception).

    Parameters
    ----------
    prefix : str, optional
        Text prepended to the stack trace—handy for contextual markers.
    """
    stack_str = traceback.format_exc()
    if prefix:
        stack_str = f"{prefix.rstrip()}:\n{stack_str}"
    log_debug(stack_str, "ObfAnalysis")


def user_error(msg: str, *, exc: Exception | None = None) -> None:
    """
    Emit a single, user-visible error line and (optionally) dump the
    full traceback to the Debug log.

    Typical usage inside an `except` block:

    .. code-block:: python

        try:
            ...
        except Exception as err:
            user_error("Translation failed.", exc=err)

    Parameters
    ----------
    msg : str
        Short, high-level explanation.
    exc : Exception, optional
        The caught exception.  When provided, a full stack trace is visible only when the user
        enables Debug Log in Binary Ninja.  If `None` (default), no
        traceback is emitted.
    """
    # log user error
    log_error(f"{msg}", "ObfAnalysis")
    # stacktrace
    if exc is not None:
        log_stacktrace("Stacktrace:")
