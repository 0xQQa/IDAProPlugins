from os import path as o_path
from sys import path as s_path

project_root = o_path.abspath(o_path.join(o_path.dirname(__file__), '..'))
if project_root not in s_path:
    s_path.insert(0, project_root)

from Internal.SyscallParser import SyscallParserCls
from sys import stderr, argv
from argparse import ArgumentParser


class SyscallParserClsCLI(SyscallParserCls):

	def __init__(self) -> None:
		parser = self.__setup_args_parser()
		if len(argv) == 1:
			parser.print_help(stderr)
			return

		args = parser.parse_args()
		if args.show_supported:
			self.__supported_versions_hint()
			return

		if not args.syscall_numbers:
			parser.print_help(stderr)
			return

		system_name = args.system_name.replace(" ", "")
		system_version = args.system_version.replace(" ", "")
		super().__init__(args.architecture, system_name, system_version)
		
		self.__get_results(args.syscall_numbers, system_name, system_version, args.architecture)

	def __setup_args_parser(self) -> ArgumentParser:
		parser = ArgumentParser(description=self._DESCRIPTION)
		parser.add_argument('-a', '--architecture', default="x64", choices=self._SUPPORTED_VERSIONS, help="Choosen architecture")
		parser.add_argument('-n', '--system_name', default="Windows 10",  help="Windows system name (can be typed without spaces)")
		parser.add_argument('-v', '--system_version', help="Windows version, depends on system name (can be typed without spaces)")
		parser.add_argument('-c', '--syscall_numbers', help="Syscall number/numbers - could be hex (starts with 0x) or decimal value, divided by ','") 
		parser.add_argument('-sup', '--show_supported', action="store_true", help="Show supported versions of architecture, system_name and system_versions")

		return parser

	def __supported_versions_hint(self) -> None:		
		json_object = self.get_supported_versions()
		print("Layout -> {... Architecture:{... System Name: [... System Versions")
		print(json_object)

	def __get_results(self, syscalls_no:str, system_name:str, system_version:str, architecture:str) -> None:
		resolved_syscalls = self._try_resolve(syscalls_no)
		prompt_helper = f"{system_name}/{system_version}_{architecture}"
		
		print(f"Resovled syscalls for {prompt_helper}:")
		print(resolved_syscalls)


if __name__ == "__main__":
	SyscallParserClsCLI()
