from idaapi import action_handler_t, get_screen_ea, AST_ENABLE_ALWAYS, get_imagebase
from ida_kernwin import get_highlight, get_current_viewer
from abc import ABC, abstractmethod
from typing import Tuple
from PyQt5.QtWidgets import QMessageBox

from .Imports import *


class SyscallsParserHandler(ABC, action_handler_t):

    def __init__(self, syscall_parser:SyscallParserCls) -> None:
        action_handler_t.__init__(self)
        self.parser = syscall_parser

    def update_parser(self, parser:SyscallParserCls) -> None:
        self.parser = parser

    def __prompt_not_inited(self) -> None:
        popup_msg = QMessageBox()
        popup_msg.setWindowTitle("Syscall Parser not initalized")
        popup_msg.setText("You need to initliaze config in Edit->Plugins->Syscall Parser Config!")
        popup_msg.exec()

    def _get_api_name_from_selection(self) -> Tuple[str, int, int]:
        if self.parser is None:
            self.__prompt_not_inited()
            return None, None, None

        choosen_data = get_highlight(get_current_viewer())
        if not choosen_data or len(choosen_data) != 2:
            return None, None, None
            
        try:
            syscall_no = choosen_data[0] 
            syscall_no, enc = (syscall_no, 10) if "h" not in syscall_no else (syscall_no[:-1], 16)
            syscall_no = int(syscall_no, enc)
        except:
            return None, None, None
        
        ea = get_screen_ea()
        api_name = self.parser.resolve_one(syscall_no, plain=True)
        return api_name, syscall_no, ea
    
    def _update_api_name_from_syscall(self, syscall_no:int) -> str:
        api_name = self.parser.resolve_one(syscall_no, plain=True)
        return api_name
    
    def update(self, ctx) -> int:               #todo ctx
        return AST_ENABLE_ALWAYS

    @abstractmethod
    def reset_data(self) -> None:
        ...

    @abstractmethod
    def try_migrate(self) -> None:
        ...
    
    @abstractmethod
    def term(self) -> None:
        ...
