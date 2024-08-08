from json import load, dumps
from pkg_resources import resource_filename
from typing import Tuple, List, Dict


class SyscallParserCls:
	_DESCRIPTION = "A tool that allows you to quickly get the Windows api name from syscall for the selected version of Windows operating system (using j00ru syscall table list)"
	_SUPPORTED_VERSIONS = 'x64', 'x86'
	__RESORCES_LOCATION = ".\\Resources"
	__RESOURCE_NAME = "nt-per-system.json"

	def __init__(self, *args:List[str]) -> None:	
		match len(args):
			case 1:
				self.syscall_data = args[0]
				result = True #todo valdiate
			case 3:
				result, self.syscall_data = self.__resolve_syscalls_data(*args)
			case _:
				result = False
				
		if not result:
			...
			#err

	def resolve_one(self, syscall_no:int, plain:bool=False) -> str|int:
		get_key_from_val_internal = lambda search_val: (api_name for api_name, api_val in self.syscall_data.items() if api_val == search_val)
		get_key_from_val = lambda search_val: next(get_key_from_val_internal(search_val), "Syscall not found!")
		result = get_key_from_val(syscall_no)
		
		if not plain:
			result = f"{syscall_no:#06x} -> {result}"

		return result

	def __resolve_many(self, syscalls_no:str) -> Tuple[bool, str]:
		parse_to_int = lambda val: int(val, 16 if "0x" in val else 10)

		syscalls_no = syscalls_no.split(",")
		syscalls_no = map(parse_to_int, syscalls_no)
		syscalls_names = map(self.resolve_one, syscalls_no)

		try:
			syscalls_names = str.join("\n", syscalls_names)
		except:
			return False, "Unknown int base! Use decimal or hexdecimal numbers (hex starts with 0x)!"

		return True, syscalls_names

	def __resolve_syscalls_data(self, arch:str, system_name:str, system_version:str) -> Tuple[bool, dict|str]:
		def parse_spaces_in_data(looked_key:str, tmp_data:dict) -> str|None:
			tmp_keys = map(lambda key: key.replace(" ", ""), tmp_data.keys())
			tmp_keys_dict = dict(zip(tmp_keys, tmp_data.keys()))
			if looked_key not in tmp_keys_dict.keys():
				return None

			return tmp_keys_dict[looked_key]

		resource_path = f"{self.__RESORCES_LOCATION}/{arch}/{self.__RESOURCE_NAME}"
		static_resource_path = self.__static_file_path(resource_path)
		if not static_resource_path:
			return f"Can't find resource file: {resource_path}"

		with open(static_resource_path, "r") as tmp_f:
			data = load(tmp_f)

		system_name = parse_spaces_in_data(system_name, data)
		if not system_name:
			return False, "Unknown system name! Run with hint to see supported!"

		system_version = parse_spaces_in_data(system_version, data[system_name])
		if not system_version:
			return False, "Unknown system version! Run with hint to see supported!"

		syscalls_data = data[system_name][system_version]
		return True, syscalls_data

	def _try_resolve(self, syscalls_no:str) -> str:
		_, resolved_syscalls = self.__resolve_many(syscalls_no)
		return resolved_syscalls
		
	@staticmethod
	def __static_file_path(resource_path:str) -> str|None:
		try:
			resource = resource_filename(__name__, resource_path)
		except KeyError:
			return None

		return resource

	@staticmethod
	def get_requested_resource_chunk(architecture:str, system_name:str, system_version:str) -> Dict|None:
		resource_path = f"{SyscallParserCls.__RESORCES_LOCATION}/{architecture}/{SyscallParserCls.__RESOURCE_NAME}"
		static_resource_path = SyscallParserCls.__static_file_path(resource_path)
		if not static_resource_path:
			return None

		with open(static_resource_path, "r") as tmp_f:
			data = load(tmp_f)
		
		syscalls_data = data[system_name][system_version]
		return syscalls_data

	@staticmethod
	def get_supported_versions() -> str:
		supported_syscalls = {}

		for arch in SyscallParserCls._SUPPORTED_VERSIONS:
			resource_path = f"{SyscallParserCls.__RESORCES_LOCATION}/{arch}/{SyscallParserCls.__RESOURCE_NAME}"
			static_resource_path = SyscallParserCls.__static_file_path(resource_path)
			if not static_resource_path:
				return f"Can't find resource file: {resource_path}"

			with open(static_resource_path, "r") as tmp_f:
				data = load(tmp_f)

			supported_systems = data.keys()
			supported_versions = map(lambda supported_system: list(data[supported_system].keys()), supported_systems)
			supported_systems_versions = dict(zip(supported_systems, supported_versions))
			supported_syscalls[arch] = supported_systems_versions
		
		json_object = dumps(supported_syscalls, indent=4)
		return json_object
