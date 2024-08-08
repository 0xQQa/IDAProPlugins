from ida_enum import get_enum, add_enum, add_enum_member, del_enum, get_next_enum_member, get_enum_member, get_enum_member_value, get_first_enum_member, get_enum_member_name, set_enum_member_name
from idaapi import BADADDR, get_item_head
from ida_bytes import op_enum, clr_op_type
from idc import is_code, get_operand_value, get_full_flags, del_items
from idautils import XrefsTo

from .Imports import *


class EnumHndlr(SyscallsParserHandler):
    __ENUM_NAME = "SYSCALLS_NO"
    __ENUM_PREFIX = "sc_"

    def __init__(self, syscall_parser:SyscallParserCls) -> None:
        super().__init__(syscall_parser)

    def __update_enum(self, api_name:str, syscall_no: int) -> int:
        enum_id = get_enum(self.__ENUM_NAME)
        if enum_id == BADADDR:
            enum_id = add_enum(4, self.__ENUM_NAME, 0)

        was_added = add_enum_member(enum_id, api_name, syscall_no)
        if was_added:
            ...
            #maybe check

        return enum_id
    
    def __place_enum(self, ea: int, enum_id: int, highlight: int) -> bool:
        start = get_item_head(ea)

        if not is_code(get_full_flags(ea)):
            clr_op_type(start, 0)
            return op_enum(start, 0, enum_id, 0)
        
        if get_operand_value(ea, 0) == highlight:
            clr_op_type(start, 0)
            return op_enum(start, 0, enum_id, 0)
            
        if get_operand_value(ea, 1) == highlight:
            clr_op_type(start, 1)
            return op_enum(start, 1, enum_id, 0)

        return False
        
    def activate(self, ctx) -> bool:
        api_name, syscall_no, ea = self._get_api_name_from_selection()
        if not api_name:
            return False
            
        enum_api_name = self.__ENUM_PREFIX + api_name
        enum_id = self.__update_enum(enum_api_name, syscall_no)
        if not enum_id:
            return False

        result = self.__place_enum(ea, enum_id, syscall_no)
        return result

    def reset_data(self) -> None:
        enum_id = get_enum(self.__ENUM_NAME)
        if enum_id == BADADDR:
            return
            
        member = get_first_enum_member(enum_id)
        while member != BADADDR:
            member_addr = get_enum_member(enum_id, member, 0, 0)
            syscall_no = get_enum_member_value(member_addr)
            for xref in XrefsTo(member_addr):
                ea = xref.frm
                op_idx =  None

                if get_operand_value(ea, 0) == syscall_no:
                    op_idx = 0
                elif get_operand_value(ea, 1) == syscall_no:
                    op_idx = 1

                if op_idx is None:
                    #err?
                    continue
                
                clr_op_type(ea, op_idx)

            member = get_next_enum_member(enum_id, member, 0)

        del_enum(enum_id)
           
    def try_migrate(self) -> None:
        enum_id = get_enum(self.__ENUM_NAME)
        if enum_id == BADADDR:
            return

        member = get_first_enum_member(enum_id)
        while member != BADADDR:
            member_addr = get_enum_member(enum_id, member, 0, 0)

            syscall_no = get_enum_member_value(member_addr)
            old_api_name = get_enum_member_name(member_addr)[len(self.__ENUM_PREFIX):]
            new_api_name = self._update_api_name_from_syscall(syscall_no)
           
            print(f"SyscallParser: Updated syscall enum no. {syscall_no:#06x}: {old_api_name} -> {new_api_name}")

            new_api_name = self.__ENUM_PREFIX + new_api_name
            set_enum_member_name(member_addr, new_api_name)
            member = get_next_enum_member(enum_id, member, 0)

        return 
        
    def term(self) -> None:
        ...
