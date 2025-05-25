"""
Binary Ninja plugin entrypoint for *Obfuscation Analysis*.

Registers UI commands, user-visible settings, and wires them to the
background-thread helpers.
"""
from pathlib import Path
from binaryninja import PluginCommand
from binaryninja.settings import Settings

from .obfuscation_analysis import (identify_corrupted_functions_bg,
                                   remove_corrupted_functions_bg,
                                   simplify_hlil_instruction_bg)

# ----------------------------------------------------------------------
#  Command registrations
# ----------------------------------------------------------------------

PluginCommand.register_for_high_level_il_instruction(
    "Obfuscation Analysis\\MBA Simplification\\Slice && Simplify",
    (
        "Back-slice the selected HLIL expression, translate it to Miasm IR, "
        "run msynth for Mixed-Boolean Arithmetic (MBA) simplification, and "
        "annotate the result as a decompiler comment."
    ),
    simplify_hlil_instruction_bg,
)

PluginCommand.register(
    "Obfuscation Analysis\\Corrupted Functions\\Identify Corrupted Functions",
    (
        "Scan the binary for functions that contain undefined or overlapping "
        "instructions (typical artefacts of failed disassembly)."
    ),
    identify_corrupted_functions_bg,
)

PluginCommand.register(
    "Obfuscation Analysis\\Corrupted Functions\\Remove Corrupted Functions",
    (
        "Remove all functions with corrupted disassembly from the BinaryView "
        "and trigger re-analysis to clean up the function list."
    ),
    remove_corrupted_functions_bg,
)

# ----------------------------------------------------------------------
#  User-visible settings
# ----------------------------------------------------------------------

plugin_dir = Path(__file__).resolve().parent
mba_oracle_path = f"{plugin_dir}/msynth_oracle.pickle"

Settings().register_group("obfuscation_analysis", "Obfuscation Analysis")
Settings().register_setting(
    "obfuscation_analysis.mba_oracle_path",
    f'''{{
        "description" : "Absolute path to the oracle database shipped with msynth. Required for MBA simplification.", 
        "title" : "msynth Oracle DB Path", 
        "default" : "{mba_oracle_path}", 
        "type" : "string",
        "requiresRestart": true,
        "optional": false,
        "uiSelectionAction": "file"
    }}'''
)
