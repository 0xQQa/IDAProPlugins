from PyQt5.QtWidgets import QDialog, QWidget, QLabel, QComboBox, QPushButton, QSizePolicy, QSpacerItem, QHBoxLayout, QVBoxLayout, QFormLayout, QMessageBox
from PyQt5.QtCore import Qt
from json import loads
from enum import IntEnum

from .Imports import *


class CfgFormResult(IntEnum):
    SAVE = 1
    CANCEL = 2
    RESET = 3


class SyscallParserCfgForm(QDialog):
    __WINDOW_TITLE = "Syscall Parser Config"
    
    def __init__(self, manager: SyscallParserIDAManager, parent:QWidget) -> None:
        super(SyscallParserCfgForm, self).__init__(parent)

        self.cfg = manager.cfg
        self.supported_versions_dict = loads(SyscallParserCls.get_supported_versions())
        buttons_layout = self.__init_buttons()
        comboboxes_layout, self.system_architecture_combo, self.system_name_combo, self.system_version_combo = self.__init_comboboxes()
        self.__set_form_layout(buttons_layout, comboboxes_layout)

    def __init_buttons(self) -> QHBoxLayout:
        save_button = QPushButton('Save')
        save_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        save_button.clicked.connect(self.__on_save)

        cancel_button = QPushButton('Cancel')
        cancel_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        cancel_button.clicked.connect(self.__on_cancel)

        reset_button = QPushButton('Reset')
        reset_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        reset_button.clicked.connect(self.__on_reset)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(save_button)
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addWidget(reset_button)

        spacer = QSpacerItem(10, 10, QSizePolicy.Minimum, QSizePolicy.Minimum)
        buttons_layout.addItem(spacer)
        
        return buttons_layout

    def __init_comboboxes(self) -> tuple[QVBoxLayout, QComboBox, QComboBox, QComboBox]:
        system_architecture = QLabel(f"{SyscallParserCfg._SYSTEM_ARCHITECTURE}:")
        system_architecture_combo = QComboBox()

        system_name = QLabel(f"{SyscallParserCfg._SYSTEM_NAME}:")
        system_name_combo = QComboBox()

        system_version = QLabel(f"{SyscallParserCfg._SYSTEM_VERSION}:")
        system_version_combo = QComboBox()

        spacer = QSpacerItem(10, 10, QSizePolicy.Minimum, QSizePolicy.Minimum)

        user_info_layout = QVBoxLayout()
        user_info_layout.addWidget(system_architecture)
        user_info_layout.addWidget(system_architecture_combo)
        user_info_layout.addItem(spacer)
        user_info_layout.addWidget(system_name)
        user_info_layout.addWidget(system_name_combo)
        user_info_layout.addItem(spacer)
        user_info_layout.addWidget(system_version)
        user_info_layout.addWidget(system_version_combo)

        architectures = list(self.supported_versions_dict.keys())
        system_architecture_combo.addItems(architectures)
        system_architecture_combo.setCurrentIndex(-1)
        system_architecture_combo.currentIndexChanged.connect(self.__architecture_change)
        system_name_combo.currentIndexChanged.connect(self.__system_name_change)

        return user_info_layout, system_architecture_combo, system_name_combo, system_version_combo

    def __set_form_layout(self, buttons_layout: QHBoxLayout, comboboxes_layout: QVBoxLayout) -> None:
        app_form_layout = QFormLayout()
        app_form_layout.addItem(comboboxes_layout)
        app_form_layout.addItem(buttons_layout)
        self.setLayout(app_form_layout)
        self.setWindowFlags(Qt.WindowCloseButtonHint)
        self.setWindowTitle(self.__WINDOW_TITLE)

    def __architecture_change(self, index:int) -> None:
        self.system_name_combo.clear()
        self.system_version_combo.clear()
        self.system_version_combo.setCurrentIndex(-1) 

        if index == -1:
            return
        
        choosen_arch = self.system_architecture_combo.currentText()
  
        avalible_system_names = list(self.supported_versions_dict[choosen_arch].keys())
        self.system_name_combo.addItems(avalible_system_names)
        self.system_name_combo.setCurrentIndex(-1)

    def __system_name_change(self, index:int) -> None:
        self.system_version_combo.clear()

        if index == -1:
            return

        choosen_arch =  self.system_architecture_combo.currentText()
        choosen_system_name = self.system_name_combo.currentText()
        
        avalible_system_versions = self.supported_versions_dict[choosen_arch][choosen_system_name]
        self.system_version_combo.addItems(avalible_system_versions)
        self.system_version_combo.setCurrentIndex(-1)

    def __on_cancel(self) -> None:
        if self.cfg.has_cache_data():
            system_architecture, system_name, system_version = self.cfg.get_cache_data()
            self.system_architecture_combo.setCurrentText(system_architecture)
            self.system_name_combo.setCurrentText(system_name)
            self.system_version_combo.setCurrentText(system_version)
        else:
            self.system_architecture_combo.setCurrentIndex(-1)
            self.system_name_combo.setCurrentIndex(-1)
            self.system_version_combo.setCurrentIndex(-1)

        self.done(CfgFormResult.CANCEL)

    def __on_save(self) -> None:
        system_architecture = self.system_architecture_combo.currentText()
        system_name = self.system_name_combo.currentText()
        system_version = self.system_version_combo.currentText()

        if any(map(lambda sys_var: sys_var == "", (system_architecture, system_name, system_version))):   
            return                                                                                 

        self.cfg.dump(system_architecture, system_name, system_version)
        self.done(CfgFormResult.SAVE)

    def __on_reset(self) -> None:
        def make_sure():
            popup_msg = QMessageBox()
            popup_msg.setWindowTitle("Syscall Parser reset")
            popup_msg.setText("Are you sure? This action will delete all created comments and enums.")
            popup_msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            popup_msg.setDefaultButton(QMessageBox.No)
            return popup_msg.exec()

        if make_sure() == QMessageBox.No:
            return

        self.system_architecture_combo.setCurrentIndex(-1)
        self.system_name_combo.setCurrentIndex(-1)
        self.system_version_combo.setCurrentIndex(-1)
        self.cfg.delete()

        self.done(CfgFormResult.RESET)

    def on_start(self) -> None:
        if not self.cfg.has_cache_data():
            return

        system_architecture, system_name, system_version = self.cfg.get_cache_data()

        self.system_architecture_combo.setCurrentText(system_architecture)
        self.system_name_combo.setCurrentText(system_name)
        self.system_version_combo.setCurrentText(system_version)
        