from typing import Iterable

from binaryninja.binaryview import BinaryView
from binaryninja.function import Function
from binaryninja.highlevelil import HighLevelILInstruction

from .mba.simplifer import get_simplifier
from .mba.slicing import backward_slice_basic_block_level
from .utils import find_corrupted_functions, user_error


def simplify_hlil_mba_slice_at(
    bv: BinaryView,
    instruction: HighLevelILInstruction,
) -> None:
    """
    Slice-and-simplify one HLIL instruction with msynth and drop the
    result as a user comment.

    Workflow
    --------
    1. Backward slice (single BB) –  
       `backward_slice_basic_block_level` resolves the instruction’s SSA
       dependency chain and translates the fully-inlined expression to
       Miasm IR.
    2. MBA simplification –  
       The cached simplifier canonicalises the Mixed-
       Boolean Arithmetic (MBA) expression.
    3. Annotate –  
       The simplified expression is attached as a decompiler comment at the
       instruction’s address.

    Error handling
    --------------
    * Any failure in translation or simplification is caught locally.  
    * A concise red line appears in Binary Ninja’s log; the full traceback
      is available when *Debug Log* is enabled.  
    * The function then returns early, leaving no partial comment behind.

    Parameters
    ----------
    bv :
        The active :class:`BinaryView`; needed only for architecture
        pointer-size information inside the slice routine.
    instruction :
        The HLIL instruction currently selected by the user.

    Side effects
    ------------
    * On success, a comment is written into
      ``instruction.function.source_function`` at `instruction.address`.
    * No value is returned; caller need not inspect a result.
    """

# backward slice in SSA form
    try:
        expr_m2 = backward_slice_basic_block_level(
            bv, instruction, instruction.function.ssa_form)
        # if assignment, only take right-hand side
        if expr_m2.is_assign():
            expr_m2 = expr_m2.src
    except Exception as err:
        user_error(
            f"Failed to translate HLIL expression at {hex(instruction.address)} to Miasm IR: {err}", exc=err)
        return

    # get simplifier
    simplifier = get_simplifier()
    if simplifier is None:
        return

    # simplify
    try:
        simplified = simplifier.simplify(expr_m2)
    except Exception as err:
        user_error(
            f"Could not simplify HLIL expression at address {hex(instruction.address)} using msynth: {err}", exc=err)
        return

    # add simplified expression as comment
    instruction.function.source_function.set_comment_at(
        instruction.address,
        str(simplified).replace("#0", ""),
    )


def identify_corrupted_functions(bv: BinaryView) -> None:
    """
    Emit a diagnostic list of functions with corrupted disassembly.

    A function is treated as corrupted, which typically happens if the linear sweep 
    created overlapping or undefined instructions—common in packed/obfuscated binaries.

    Parameters
    ----------
    bv : BinaryView
        Active BinaryView to scan.
    """
    for func in find_corrupted_functions(bv):
        print(f"Corrupted disassembly at {func.name} (0x{func.start:x})")


def remove_corrupted_functions(bv: BinaryView) -> None:
    """
    Remove (undefine) every corrupted function and force Binary Ninja to
    re-analyse the binary.

    Useful for cleaning up the function list when heavy obfuscation causes
    a flood of bogus or partially decoded functions.

    Note: In some cases this might be too aggressive.

    Parameters
    ----------
    bv : BinaryView
        Active BinaryView to clean up.
    """
    for func in find_corrupted_functions(bv):
        print(f"Removing corrupted function {func.name} (0x{func.start:x})")
        bv.remove_function(func)

    # Enforce re-analysis
    bv.update_analysis()
