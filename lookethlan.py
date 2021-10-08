#!/usr/bin/env python3
#    Look@Lan - A simple network scanner.
#    Copyright (C) 2021 - xopr - xopr@ackspace.nl
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License or any
#    later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    A copy of the GNU General Public License version 3 named LICENSE is
#    in the root directory of this project.
#    If not, see <https://www.gnu.org/licenses/licenses.en.html#GPL>.

# -*- coding: utf-8 -*-
"""
LookEthLan main application
"""
import getopt
import logging
import os
import platform
import sys
import time
from enum import Enum
from datetime import datetime
from ipaddress import ip_network
from netifaces import interfaces, ifaddresses, AF_INET, AF_INET6, gateways
from pathlib import Path

isWindows = platform.system().lower() == "windows"

# need to set the correct cwd
CURRENT_DIR = Path(__file__).parent
sys.path.insert(0, str(CURRENT_DIR))
os.chdir(CURRENT_DIR)

from PyQt5 import QtCore
from PyQt5.QtCore import (
    Qt, 
    QObject,
    QRect,
    QSize,
    QThread,
    QTimer,
    pyqtSignal,
    pyqtSlot 
)
from PyQt5.QtGui import (
    QIcon,
    QPixmap,
    QStandardItem,
    QStandardItemModel
)
from PyQt5.QtWidgets import (
    QComboBox,
    QStyle,
    QMainWindow,
    QApplication,
    QAction,
    QFileDialog,
    QLabel,
    QToolButton,
    QWidget,
    QGridLayout,
    QVBoxLayout,
    QPushButton,
    QSpacerItem,
    QSizePolicy,
    QMenuBar,
    QMenu,
    QStatusBar,
    QAbstractItemView,
    QMessageBox,
    QDesktopWidget,
    QHBoxLayout,
    QLineEdit
)

from tables import (
    HostTable, 
    LanTableModel, 
    IPItem
)

import scanner

LOG_FORMAT = "[%(levelname)s] - { %(name)s }: %(message)s"
logger = logging.getLogger()

# Used for create_row
class ColumnType(Enum):
    STRING = 0,
    IP = 1,
    ONLINE = 2,
    MS = 3,
    HOPS = 4,
    TIMESTAMP = 5,
    SNMP = 6

COLUMNS = { 
    "ip":       ColumnType.IP,
    "online":   ColumnType.ONLINE,
    "latency":  ColumnType.MS,
    "hops":     ColumnType.HOPS,
    "ts":       ColumnType.TIMESTAMP,
    "fqdn":     ColumnType.STRING,
    "netbios":  ColumnType.STRING,
    "snmp":     ColumnType.SNMP
}

COLUMN_NAMES = { 
    "ip":       "IP Address",
    "online":   "Status",
    "hops":     "Distance",
    "latency":  "Ping",
    "os":       "O.S.",
    "fqdn":     "Hostname",
    "netbios":  "NetBIOS Name",
    #"nbuser":   "NetBIOS User",
    "snmp":     "SNMP",
    "trap":     "Trap",
    "ts":       "Last update"
}

class Worker(QObject):
    finished = pyqtSignal(dict)
    
    def __init__(self,fn):
        super().__init__()
        self.fn = fn
    

    def run(self):
        """Long-running task."""
        result = self.fn()
        self.finished.emit( result )


class MainWindow(QMainWindow):
    """
    The main window.
    """
    thread = None
    concurrent_threads = 0
    
    def __init__(self):
        super().__init__()

        self.ethScanner = scanner.EthScanner()
        self.init_ui()


    def init_ui(self):
        self.setWindowTitle("LookðLan")
        self.resize(1150, 770)
        self.center()
        self.setWindowIcon(QIcon("./img/crosshair.png"))


        # Icons
        find_icon = QIcon.fromTheme("edit-find")
        manage_icon = QIcon.fromTheme("insert-object")
        settings_icon = QIcon.fromTheme("preferences-system")

        new_icon = QIcon(
            self.style().standardIcon(QStyle.SP_FileDialogNewFolder)
        )
        exit_icon = QIcon(
            self.style().standardIcon(QStyle.SP_BrowserStop)
        )
        reload_icon = QIcon(
            self.style().standardIcon(QStyle.SP_BrowserReload)
        )
        delete_icon = QIcon(
            self.style().standardIcon(QStyle.SP_TrashIcon)
        )
        folder_icon = QIcon(
            self.style().standardIcon(QStyle.SP_DirOpenIcon)
        )
        qt_icon = QIcon(
            self.style().standardIcon(QStyle.SP_TitleBarMenuButton)
        )
        info_icon = QIcon(
            self.style().standardIcon(QStyle.SP_FileDialogInfoView)
        )

        # layouts
        centralwidget = QWidget(self)
        grid_layout = QGridLayout(centralwidget)

        v_layout_1 = QVBoxLayout()
        v_layout_2 = QVBoxLayout()
        h_layout_1 = QHBoxLayout()

        v_layout_1.setContentsMargins(12, 19, 5, -1)
        v_layout_2.setContentsMargins(-1, 4, 6, -1)

        # buttons
        self.scan_button = QPushButton(
            "&Scan",
            centralwidget,
            statusTip="Start scanning",
            clicked=self.scan
        )
        self.scan_button.setMinimumSize(QSize(150, 0))

        self.exit_button = QPushButton(
            "Quit",
            centralwidget,
            statusTip="Quit Application",
            clicked=self.on_close
        )

        # use line edit to store the str
        self.directory_line = QLineEdit()

        self.rescan_button = QToolButton(
            icon=reload_icon,
            toolTip="Refresh lists",
            statusTip="Refresh interface and network list",
            clicked=self.populate_network_settings
        )
        self.rescan_button.setFixedSize(30, 30)
        
        self.interface_combobox = QComboBox(
            toolTip="Interface",
            statusTip="Selects interface",
            #clicked=self.scan
        )
        self.interface_combobox.setMaximumWidth(150)
        
        self.network_combobox = QComboBox(
            toolTip="Network",
            statusTip="Selects network to scan",
            #clicked=self.scan
        )
        self.network_combobox.setEditable( True )
        #self.network_combobox.setInsertPolicy( QComboBox.NoInsert )

        # spacer between manage button and exit button
        spacer_item_1 = QSpacerItem(
            20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding
        )

        #v_layout_2.addWidget(self.logo)
        v_layout_2.addWidget(self.scan_button)

        v_layout_2.addItem(spacer_item_1)
        v_layout_2.addWidget(self.exit_button)

        grid_layout.addLayout(v_layout_2, 0, 1, 1, 1)


        # tables

        # interpreter table header
        interpreter_table_label = QLabel(
            '<span style="font-size: 13pt;">\
                <b>Found hosts</b>\
            </span>',
            centralwidget
        )

        # interpreter table
        self.interpreter_table = HostTable(
            centralwidget,
            selectionBehavior=QAbstractItemView.SelectRows,
            editTriggers=QAbstractItemView.NoEditTriggers,
            alternatingRowColors=True,
            sortingEnabled=True,
            drop_item=self.populate_host_table
        )

        # hide vertical header
        self.interpreter_table.verticalHeader().hide()

        # adjust (horizontal) headers
        h_header_interpreter_table = self.interpreter_table.horizontalHeader()
        h_header_interpreter_table.setDefaultAlignment(Qt.AlignLeft)
        h_header_interpreter_table.setDefaultSectionSize(180)
        h_header_interpreter_table.setStretchLastSection(True)

        # set table view model
        self.model_interpreter_table = QStandardItemModel(0, 2, centralwidget)
        #self.model_interpreter_table = LanTableModel( 0, 2, centralwidget )
        
        self.model_interpreter_table.setHorizontalHeaderLabels(
            map(lambda col : COLUMN_NAMES[col], COLUMNS)
        )
        self.interpreter_table.setModel(self.model_interpreter_table)

        # spacer between interpreter table and venv table title
        spacer_item_2 = QSpacerItem(
            20, 12, QSizePolicy.Minimum, QSizePolicy.Fixed
        )
        
        # add widgets to layout
        v_layout_1.addWidget(interpreter_table_label)
        v_layout_1.addWidget(self.interpreter_table)
        v_layout_1.addItem(spacer_item_2)
        v_layout_1.addLayout(h_layout_1)
        h_layout_1.addWidget(self.rescan_button)
        h_layout_1.addWidget(self.interface_combobox)
        h_layout_1.addWidget(self.network_combobox)

        grid_layout.addLayout(v_layout_1, 0, 0, 1, 1)

        self.setCentralWidget(centralwidget)

        # create actions
        self.action_exit = QAction(
            exit_icon,
            "&Quit",
            self,
            statusTip="Quit application",
            shortcut="Ctrl+Q",
            triggered=self.on_close
        )

        self.action_about_qt = QAction(
            qt_icon,
            "About &Qt",
            self,
            statusTip="About Qt",
            shortcut="Ctrl+Q",
            triggered=self.info_about_qt
        )

        # Menu
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)

        """
        menu_bar = QMenuBar(self)
        menu_bar.setGeometry(QRect(0, 0, 740, 24))
        self.setMenuBar(menu_bar)

        menu_venv = QMenu("&LookðLan", menu_bar)
        menu_venv.addAction(self.action_exit)
        menu_bar.addAction(menu_venv.menuAction())

        menu_help = QMenu("&Help", menu_bar)
        menu_help.addAction(self.action_about_qt)
        menu_bar.addAction(menu_help.menuAction())
        """
        
    def populate_network_settings(self):
        self.interface_combobox.clear()
        self.network_combobox.clear()

        self.interface_combobox.addItem( "<default>", None )

        # Note: windows is using src addresses, linux uses interfaces
        for interface in interfaces():
            ipv4s = ifaddresses( interface ).setdefault( AF_INET )
            if isWindows:
                if ipv4s:
                    for ipv4 in ipv4s:
                        if ipv4:
                            ipv4 = ipv4["addr"]
                        self.interface_combobox.addItem( "%s (%s)" % ( interface, ipv4 ), ipv4 )
                else:
                    self.interface_combobox.addItem( "%s (no ip)" % interface, interface )
            else:
                # Get the first ip address for this interface
                ipv4 = ipv4s and ipv4s[0]["addr"]
                self.interface_combobox.addItem( "%s (%s)" % (interface, ipv4), interface )

        ipv6_list = []
        for interface in interfaces():
            ipv4s = ifaddresses( interface ).setdefault( AF_INET )
            if ipv4s:
                for ipv4 in ipv4s:
                    self.network_combobox.addItem( "%s/%s" % (ipv4["addr"], ipv4["netmask"]) )

            ipv6s = ifaddresses( interface ).setdefault( AF_INET6 )
            if ipv6s:
                for ipv6 in ipv6s:
                # Note: expanded subnet masks are not supported, only prefix
                    prefix = bin( int( "".join( ipv6["netmask"].split(":") ).ljust( 32,"0" ), 16 ) ).count( "1" )
                    try:
                        #ipv6 = ip_network("%s/%s" % (ipv6[0]["addr"], prefix), False )
                        ipv6_list.append( "%s/%s" % (ipv6["addr"], prefix) )
                    except:
                        pass

        defaultif = gateways()['default'][AF_INET][1]
        defaultaddress = ifaddresses(defaultif).setdefault( AF_INET )[0]
        ip = defaultaddress["addr"]
        subnet = defaultaddress["netmask"]
        self.network_combobox.setCurrentText( "%s/%s" % (ip, subnet) )

        # TODO: add ipv6 compatibility and add the local networks to the list
        #self.network_combobox.addItems( ipv6_list )

    def center(self):
        """Center window.
        """
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())


    def on_close(self):
        """Stop all threads, then close the application.
        """
        self.close()


    def info_about_qt(self):
        """Open the "About Qt" dialog.
        """
        QMessageBox.aboutQt(self)

    def scan(self):
        """
        Start scanning.
        """
        # Sanity check
        if self.thread and self.thread.isRunning():
            return

        self.status_bar.showMessage( "0%", 15000 )

        self.thread = QThread()
        self.worker = Worker( lambda: self.ethScanner.scan( self.network_combobox.currentText(), self.interface_combobox.currentData() ) )
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.cleanup_thread)

        #self.worker.finished.connect( self.resolve_services )
        self.thread.finished.connect( self.resolve_services )

        self.set_busy( True )
        self.thread.start()
        #self.thread.finished.connect( lambda: self.set_busy( False ) )
        
        self.timer=QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(50)

    def update_status(self):
        if self.ethScanner.busy_counter > self.concurrent_threads:
            self.concurrent_threads = self.ethScanner.busy_counter
        elif self.ethScanner.busy_counter == 0:
            self.concurrent_threads = 0
        else:
            self.status_bar.showMessage( "{:.0%}".format(1 - self.ethScanner.busy_counter/self.concurrent_threads ), 1500)

    def set_busy( self, busy: bool ):
        self.scan_button.setEnabled( not busy )
        if not busy:
            self.timer.stop()

    def cleanup_thread(self):
        self.thread.deleteLater()
        self.thread = None

    def resolve_services(self):
        self.populate_host_table()

        #self.ethScanner.resolve_services(netbios=True, snmp=True, resolvename=True)
        #self.populate_host_table()
        #self.set_busy( False )

        self.thread2 = QThread()
        #self.worker2 = Worker( lambda: self.ethScanner.resolve_services(netbios=True, snmp=True, resolvename=True) )
        self.worker2 = Worker( lambda: self.ethScanner.resolve_services( netbios=True, snmp=True, resolvename=True, counthops=True ) )
        
        self.worker2.moveToThread(self.thread2)

        self.thread2.started.connect(self.worker2.run)
        self.worker2.finished.connect(self.thread2.quit)
        self.worker2.finished.connect(self.worker2.deleteLater)
        self.thread2.finished.connect(self.thread2.deleteLater)

        self.worker2.finished.connect( self.populate_host_table )

        self.thread2.start()

        self.thread2.finished.connect( lambda: self.set_busy( False ) )

    def populate_host_table(self, ip_list = None):
        """Populate the host table view.
        """
    
        if ip_list == None:
            ip_list = self.ethScanner.ip_list

        self.model_interpreter_table.setRowCount( len( ip_list ) )

        row = 0
        for ip in ip_list:
            data = ip_list[ip]

            item_row = self.create_row( ip, data )
            
            for col, item in enumerate(item_row):
                self.model_interpreter_table.setItem(
                    row, col, item
                )
            row += 1

    def create_row( self, ip: str, data: dict ):
        row = []
        
        for column in COLUMNS:
            if COLUMNS[column] == ColumnType.IP:
            
                changed = data["previous"] == None or data["online"] == data["previous"]
                item = IPItem( str(ip) )
                if data["previous"] == None:
                    item.setIcon( QIcon("./img/online-new.png") )
                elif data["previous"] == data["online"]:
                    item.setIcon( QIcon( data["online"] and "./img/online-cont.png" or "./img/offline-cont.png") )
                elif data["online"]:
                    item.setIcon( QIcon("./img/online.png") )
                else:
                    item.setIcon( QIcon("./img/offline.png") )
                row.append( item )

            elif COLUMNS[column] == ColumnType.ONLINE:
                item = QStandardItem( data["online"] and ( data["previous"] == None and "ONLINE (NEW)" or "ONLINE" ) or "OFFLINE" )
                row.append( item )

            elif COLUMNS[column] == ColumnType.MS:
                item = QStandardItem( "{}ms".format( data[column] ) )
                row.append( item )

            elif COLUMNS[column] == ColumnType.HOPS:
                item = QStandardItem( str( column in data and data[column] or "-" ) )
                row.append( item )

            elif COLUMNS[column] == ColumnType.TIMESTAMP:
                item = QStandardItem( datetime.fromtimestamp( data[column] ).strftime("%H:%M:%S") )
                row.append( item )

            elif COLUMNS[column] == ColumnType.SNMP:
                if column in data:
                    # TODO: better separation
                    name = data[column][0]
                    description = data[column][1]
                    uptime = int( data[column][2] )
                    hours, remainder = divmod(int(uptime/100), 3600)
                    minutes, seconds = divmod(remainder, 60)
                    days, hours = divmod(hours, 24)                    
                    if days:
                        uptime = "up: {d}d, {h}:{m:02d}:{s:02d}, {n}, {i}"
                    else:
                        uptime = "up: {h}:{m:02d}:{s:02d}, {n}, {i}"
                        
                    line = uptime.format(d=days, h=hours, m=minutes, s=seconds, n=name, i=description)
                    item = QStandardItem( line )
                else:
                    item = QStandardItem( "-" )
                row.append( item )
            
            else:
            #case ColumnType.STRING:
            #case _:
                value = column in data and data[column] or "-"
                if isinstance(value, list):
                    value = ", ".join( value )
                item = QStandardItem( str( value ) )
                row.append( item )




        """
        item = QStandardItem( str("fqdn" in data and data["fqdn"] or "-" ) )
        row.append( item )
        
        item = QStandardItem( "netbios" in data and str(data["netbios"] or "-" ) )
        row.append( item )
        
        item = QStandardItem( "snmp" in data and str(data["snmp"] or "-") )
        row.append( item )
        """

        return row

    def enable_features(self, state):
        """Enable or disable features.
        """
        #self.search_pypi_button.setEnabled(state)
        #self.action_search_pypi.setEnabled(state)


def with_args():
    """Execute with command-line arguments.
    """
    # get full command-line arguments
    full_cmd_arguments = sys.argv

    # ignore the first
    argument_list = full_cmd_arguments[1:]

    # tell getopts() the parameters
    short_options = "Vdh"
    long_options = ["version", "debug", "help"]

    # use try-except to cover errors
    try:
        arguments, values = getopt.getopt(
            argument_list, short_options, long_options
        )
    except getopt.error as e:
        # print error message and return error code
        err_msg = str(e)
        print(f"O{err_msg[1:]}")
        sys.exit(2)

    for arg, val in arguments:
        if arg in ("-h", "--help"):
            # show help message, then exit
            print(
                f"lookðlan {scanner.__version__}  "
                "( https://github.com/ackspace/lookethlan )\n\n"
                "    -h --help           Show this help message and exit\n"
                "    -d --debug          Print debugging output\n"
                "    -v --version        Print version and exit\n"
            )
            sys.exit(0)

        if arg in ("-d", "--debug"):
            # verbose output for debugging
            logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)

        if arg in ("-V", "--version"):
            # print version, then exit
            print(f"lookðlan {scanner.__version__}")
            sys.exit(0)



def main():
    with_args()

    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.populate_host_table()
    main_window.populate_network_settings()
    main_window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

