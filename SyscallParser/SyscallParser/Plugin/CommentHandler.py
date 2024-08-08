from idaapi import get_item_head
from idc import set_cmt, get_cmt
from idautils import Heads

from .Imports import *


class CommentHndlr(SyscallsParserHandler):
    __COMMENT_BODY = "Resolved syscall:"
    __SPACER = "->"
    
    def __add_cmt_internal(self, api_name:str, syscall_no:int, ea:int) -> None:
        comment = f"{self.__COMMENT_BODY} {syscall_no:#06x} {self.__SPACER} {api_name}"
        set_cmt(ea, comment, False)

    def activate(self, ctx) -> bool:                                            #todo ctx
        api_name, syscall_no, ea = self._get_api_name_from_selection()
        if not api_name:
            return False

        ea = get_item_head(ea)
        self.__add_cmt_internal(api_name, syscall_no, ea)
        return True
        
    def reset_data(self) -> None:
        for ea in Heads():
            comment = get_cmt(ea, False) 
            if not comment or not comment.startswith(self.__COMMENT_BODY):
                continue
                    
            set_cmt(ea, "", False)

    def try_migrate(self) -> None:                                              
        for ea in Heads():
            comment = get_cmt(ea, False) 
            if not comment or not comment.startswith(self.__COMMENT_BODY):
                continue

            try:  
                syscall_no = comment.split(self.__COMMENT_BODY)[-1].split(self.__SPACER)[0].strip()
                old_api_name = comment.split(self.__SPACER)[-1].strip()
                syscall_no = int(syscall_no, 16)
            except:
                print(f"SyscallParser: Error on renaming at {hex(ea)}")
                continue
                
            new_api_name = self._update_api_name_from_syscall(syscall_no)
            self.__add_cmt_internal(new_api_name, syscall_no, ea)
            print(f"SyscallParser: Updated syscall comment at {hex(ea)}, value {syscall_no:#06x}: {old_api_name} -> {new_api_name}")

    def term(self) -> None:
        ...
