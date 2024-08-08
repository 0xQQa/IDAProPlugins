from os import path as o_path
from sys import path as s_path

project_root = o_path.abspath(o_path.join(o_path.dirname(__file__), '..'))
if project_root not in s_path:
    s_path.insert(0, project_root)

#mock to avoid circular dependencies for SyscallParserCfgForm
class SyscallParserIDAManager:
    ...

from Internal.SyscallParser import SyscallParserCls
from .Cfg import SyscallParserCfg
from .CfgForm import SyscallParserCfgForm, CfgFormResult
from .GenericHandler import SyscallsParserHandler
from .HookUI import SyscallParserHookUI
from .CommentHandler import CommentHndlr
from .EnumHandler import EnumHndlr
from .Manager import SyscallParserIDAManager