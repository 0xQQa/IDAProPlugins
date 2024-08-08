from idaapi import UI_Hooks, get_widget_type, BWN_DISASM, attach_action_to_popup

from .Imports import *


class SyscallParserHookUI(UI_Hooks):
    
    def __init__(self, action_entry:str, actions_id:list[SyscallsParserHandler]) -> None:
        UI_Hooks.__init__(self)
        self.action_entry = action_entry
        self.actions_id = actions_id

    def finish_populating_widget_popup(self, form, popup) -> None:                                  #todo 
        form_type = get_widget_type(form)
        if form_type != BWN_DISASM:
            return

        for action_id in self.actions_id:
            attach_action_to_popup(form, popup, action_id, self.action_entry)
