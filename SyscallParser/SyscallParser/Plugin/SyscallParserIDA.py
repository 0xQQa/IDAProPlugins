from idaapi import plugin_t, PLUGIN_DRAW, PLUGIN_KEEP

from .Imports import *


class SyscallParserClsIDA(plugin_t):
    flags = PLUGIN_DRAW
    comment = "Tool designed to parse syscalls"
    help = "Tool designed to parse syscalls"
    wanted_name = "Syscall Parser Config"
    wanted_hotkey = ""

    def __prompt(self, got_pre_config) -> None:
        prompt_line = "SyscallParser: initialized. " + ("Using previous saved config!" if got_pre_config else "Config not found, make one!")
        prompt_line_len = len(prompt_line)
        print("╔" + "═" * prompt_line_len + "╗")
        print("║" + prompt_line + "║")
        print("╚" + "═" * prompt_line_len + "╝")

    def init(self) -> None:
        self.syscall_ida_manager = SyscallParserIDAManager()
        got_pre_config = self.syscall_ida_manager.has_cfg()
        self.__prompt(got_pre_config)

        return PLUGIN_KEEP 

    def run(self, arg) -> None:                                     #todo
        result = self.syscall_ida_manager.try_update_cfg()
        match result:
            case CfgFormResult.SAVE:
                print("SyscallParser: Config updated!")
            case CfgFormResult.CANCEL:
                print("SyscallParser: Abort...")
            case CfgFormResult.RESET:
                print("SyscallParser: Config reset")
  
    def term(self) -> None:
        self.syscall_ida_manager.deregister()
