from os import getcwd, path, remove
from json import load, dump
from typing import Union, Tuple, Dict

from .Imports import *


class SyscallParserCfg():
    __SYSCALL_PARSER_CFG_PATH = "\\syscall_cfg.json"
    _SYSTEM_ARCHITECTURE = "System Architecture"
    _SYSTEM_NAME = "System Name"
    _SYSTEM_VERSION = "System Version"
    __CURRENT_CONFIG = {_SYSTEM_ARCHITECTURE: None, _SYSTEM_NAME: None, _SYSTEM_VERSION: None}

    def dump(self, system_architecture:str, system_name:str, system_version:str) -> None:
        self.__CURRENT_CONFIG[self._SYSTEM_ARCHITECTURE] = system_architecture
        self.__CURRENT_CONFIG[self._SYSTEM_NAME] = system_name
        self.__CURRENT_CONFIG[self._SYSTEM_VERSION] = system_version

        static_resource_path = getcwd() + self.__SYSCALL_PARSER_CFG_PATH
        with open(static_resource_path, "w") as tmp_f:
            dump(self.__CURRENT_CONFIG, tmp_f, indent=4)

    def load(self) -> Tuple[str, str, str]:
        static_resource_path = getcwd() + self.__SYSCALL_PARSER_CFG_PATH
        with open(static_resource_path, "r") as tmp_f:
            self.__CURRENT_CONFIG = load(tmp_f)

        system_architecture = self.__CURRENT_CONFIG[self._SYSTEM_ARCHITECTURE]
        system_name = self.__CURRENT_CONFIG[self._SYSTEM_NAME]
        system_version = self.__CURRENT_CONFIG[self._SYSTEM_VERSION]

        return system_architecture, system_name, system_version

    def try_init_cfg(self) -> None:
        if not self.exists():
            return
        
        self.load()
    
    def exists(self) -> bool:
        static_resource_path = getcwd() + self.__SYSCALL_PARSER_CFG_PATH
        if not path.exists(static_resource_path):
            return False
        
        return True
        
    def has_cache_data(self) -> bool:
        cfg_values = list(self.__CURRENT_CONFIG.values())
        return all(map(lambda value: value is not None, cfg_values))

    def get_cache_data(self) -> Union[Tuple[None, None, None], Tuple[str, str, str]]:
        cfg_values = list(self.__CURRENT_CONFIG.values())
        if not self.has_cache_data():
            return None, None, None
        
        return cfg_values
    
    def get_syscalls_data_chunk(self) -> Dict:
        if not self.has_cache_data():
            return None
        
        cfg_values = list(self.__CURRENT_CONFIG.values())
        syscalls_data = SyscallParserCls.get_requested_resource_chunk(*cfg_values)
        return syscalls_data
    
    def delete(self) -> None:
        if not self.exists():
            return
        
        static_resource_path = getcwd() + self.__SYSCALL_PARSER_CFG_PATH
        remove(static_resource_path)
