from __future__ import annotations

from typing import Callable, Generic, TypeVar

from binaryninja.binaryview import BinaryView
from binaryninja.highlevelil import HighLevelILInstruction
from binaryninja.plugin import BackgroundTaskThread

from .features import (
    simplify_hlil_mba_slice_at,
    identify_corrupted_functions,
    remove_corrupted_functions,
)

# ---------------------------------------------------------------------------
# Internal background-task wrappers
# ---------------------------------------------------------------------------

T = TypeVar("T")  # generic parameter type for BGTask1Param


class BGTask(BackgroundTaskThread):
    """
    Background task that forwards **only** the :class:`~binaryninja.binaryview.BinaryView`
    to the worker function.

    Parameters
    ----------
    bv :
        BinaryView on which *fn* will be executed.
    msg :
        Short status string shown in Binary Ninja’s task manager.
    fn :
        Callable expecting **one** positional argument `(bv)`.  It is run in
        the worker thread created by Binary Ninja.
    """

    def __init__(self, bv: BinaryView, msg: str, fn: Callable[[BinaryView], None]):
        super().__init__(msg, True)
        self._bv: BinaryView = bv
        self._fn: Callable[[BinaryView], None] = fn

    def run(self) -> None:
        """Entrypoint executed inside the BN worker thread."""
        self._fn(self._bv)


class BGTask1Param(BackgroundTaskThread, Generic[T]):
    """
    Background task that forwards the :class:`BinaryView` and one additional
    parameter `param` to the worker function.

    Parameters
    ----------
    bv :
        Active BinaryView.
    param :
        Extra argument forwarded verbatim to *fn*.
    msg :
        Status text for Binary Ninja’s task pane.
    fn :
        Callable expecting two positional arguments `(bv, param)`.
    """

    def __init__(
        self,
        bv: BinaryView,
        param: T,
        msg: str,
        fn: Callable[[BinaryView, T], None],
    ):
        super().__init__(msg, True)
        self._bv: BinaryView = bv
        self._param: T = param
        self._fn: Callable[[BinaryView, T], None] = fn

    def run(self) -> None:
        """Entrypoint executed inside the BN worker thread."""
        self._fn(self._bv, self._param)


# ---------------------------------------------------------------------------
# Public helpers used by the plugin’s UI commands
# ---------------------------------------------------------------------------

def simplify_hlil_instruction_bg(
    bv: BinaryView,
    instruction: HighLevelILInstruction,
) -> None:
    """
    Launch *Mixed-Boolean Arithmetic* (MBA) simplification for **one** HLIL
    instruction in a background thread.

    Workflow
    --------
    1. Slice the selected HLIL node to its basic block in SSA form.
    2. Translate the slice to Miasm IR.
    3. Pass the IR to *msynth* for MBA simplification.
    4. Attach the simplified expression as a decompiler comment.

    Parameters
    ----------
    bv :
        Active BinaryView.
    instruction :
        HLIL node picked by the user via the decompiler view.
    """
    BGTask1Param(
        bv=bv,
        param=instruction,
        msg="Simplifying MBA (BB slice)",
        fn=simplify_hlil_mba_slice_at,
    ).start()


def identify_corrupted_functions_bg(bv: BinaryView) -> None:
    """
    Start a background scan that identifies functions whose disassembly shows
    *undefined* or *overlapping* instructions—common artefacts of failed
    linear sweep or mis-decoded basic blocks.

    Parameters
    ----------
    bv :
        Active BinaryView to be inspected.
    """
    BGTask(
        bv=bv,
        msg="Scanning corrupted functions",
        fn=identify_corrupted_functions,
    ).start()


def remove_corrupted_functions_bg(bv: BinaryView) -> None:
    """
    Remove every function flagged as *corrupted* and trigger a full
    re-analysis.

    Parameters
    ----------
    bv :
        Active BinaryView to be cleaned up.
    """
    BGTask(
        bv=bv,
        msg="Removing corrupted functions",
        fn=remove_corrupted_functions,
    ).start()