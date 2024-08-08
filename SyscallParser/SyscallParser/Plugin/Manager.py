from idaapi import action_desc_t, register_action
from typing import Tuple

from .Imports import *


class SyscallParserIDAManager():

    def __init__(self) -> None:
        self.cfg = self.__init_cfg()
        self.gui_cfg = self.__init_menu_entry()
        parser = SyscallParserCls(self.cfg.get_syscalls_data_chunk()) if self.cfg.has_cache_data() else None
        self.parser_comment, self.parser_enum, self.actions = self.__init_pop_up_menu(parser)

    def __init_cfg(self) -> SyscallParserCfg:
        cfg = SyscallParserCfg()
        cfg.try_init_cfg()

        return cfg

    def __init_menu_entry(self) -> SyscallParserCfgForm:
        gui_cfg = SyscallParserCfgForm(self,  None)
        gui_cfg.on_start()
        return gui_cfg
      
    def __init_pop_up_menu(self, parser: SyscallParserCls) -> Tuple[SyscallsParserHandler, SyscallsParserHandler, SyscallParserHookUI]:
        def regsiter_action_internal(action_id, action_txt, action_handler):
            action_cls = action_handler(parser)
            action = action_desc_t(action_id, action_txt, action_cls)
            register_action(action)
            return action_cls

        action_comment_id = "syscall_parses:place_comment"
        action_comment_txt ="Place comment with Windows Api Name"
        parser_comment = regsiter_action_internal(action_comment_id, action_comment_txt, CommentHndlr)

        action_enum_id = "syscall_parses:place_enum"
        action_enum_txt ="Place enum with Windows Api Name"
        parser_enum = regsiter_action_internal(action_enum_id, action_enum_txt, EnumHndlr)
     
        actions_entry = "Syscall Parser/"
        actions = SyscallParserHookUI(actions_entry, [action_comment_id, action_enum_id])
        actions.hook()

        return parser_comment, parser_enum, actions

    def __update_config(self, parser:SyscallParserCls|None) -> None:
        self.parser_comment.update_parser(parser)
        self.parser_enum.update_parser(parser)

        if parser:
            self.parser_comment.try_migrate() 
            self.parser_enum.try_migrate() 
        else:
            self.parser_comment.reset_data() 
            self.parser_enum.reset_data() 


    def try_update_cfg(self) -> CfgFormResult:
        result = self.gui_cfg.exec()
        match result:
            case CfgFormResult.SAVE:
                parser = SyscallParserCls(self.cfg.get_syscalls_data_chunk())
            case CfgFormResult.RESET:
                parser = None
            case CfgFormResult.CANCEL:
                return CfgFormResult.CANCEL

        self.__update_config(parser)
        return result
    
    def has_cfg(self) -> bool:
        return self.cfg.has_cache_data()
    
    def deregister(self) -> None:
        if not self.actions:
            return
        
        self.actions.unhook()
