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
This module contains the tables.
"""
import webbrowser
import shutil
import os
import logging
from functools import partial

from PyQt5.QtGui import QIcon, QCursor, QStandardItemModel, QStandardItem
from PyQt5.QtCore import (
    pyqtSignal, 
    QThread, 
    QTimer, 
    QAbstractTableModel,
    Qt
)

from PyQt5.QtWidgets import (
    QStyle,
    QAction,
    QTableView,
    QMenu,
    QMessageBox,
    QFileDialog,
    QInputDialog
)

logger = logging.getLogger(__name__)



class BaseTable(QTableView):
    """The base table for all tables.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.delete_icon = QIcon(
            self.style().standardIcon(QStyle.SP_TrashIcon)
        )
        self.info_icon = QIcon(
            self.style().standardIcon(QStyle.SP_FileDialogInfoView)
        )

    def get_selected_item(self):
        """
        Return `str` from `name` column of the selected row.
        """
        listed_items = self.selectionModel().selectedRows()
        for index in listed_items:
            selected_item = index.data()
            return selected_item


    def get_comment(self):
        """
        Return `str` from `comment` column of the selected row.
        """
        index = self.currentIndex()
        row_index = self.selectionModel().selectedRows()
        row_comment = index.sibling(row_index[0].row(), 4).data()
        return row_comment


################################################################################

class HostTable(BaseTable):
    """
    List the Python installs found.
    """
    drop_item = pyqtSignal()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


    def contextMenuEvent(self, event):
        context_menu = QMenu(self)

        # pop up only if clicking on a row
        if self.indexAt(event.pos()).isValid():
            context_menu.popup(QCursor.pos())

        remove_py_action = QAction(
            self.delete_icon,
            "&Remove from list",
            self,
            statusTip="Remove this item from the table"
        )
        context_menu.addAction(remove_py_action)
        remove_py_action.triggered.connect(
            lambda: self.remove_python(event)
        )


    def remove_python(self, event):
        """Remove a Python version from the table.
        """
        item = self.get_selected_item()

        msg_box_warning = QMessageBox.warning(
            self,
            "Confirm",
            "Remove this item from list.       \n"
            "Are you sure?\n",
            QMessageBox.Yes | QMessageBox.Cancel
        )
        if msg_box_warning == QMessageBox.Yes:
        #    with open(get_data.DB_FILE, "r", encoding="utf-8") as f:
        #        lines = f.readlines()
        #    with open(get_data.DB_FILE, "w", encoding="utf-8") as f:
        #        for line in lines:
        #            if item not in line:
        #                f.write(line)

            logger.debug(f"Removed '{item}' from database")
            self.drop_item.emit()

       
################################################################################
class IPItem( QStandardItem ):
    def __lt__(self, other):
        octets1 = self.text().split(".")
        octets2 = other.text().split(".")
        for idx in range(len(octets1)): # 4
            n1 = int( octets1[idx] )
            n2 = int( octets2[idx] )
            if n1 > n2:
                return True
            if n1 < n2:
                return False
        return False
        
    def lessThan(self, left, right):
        print( "LESSTHAN" )
        leftData = self.sourceModel().data(left)
        rightData = self.sourceModel().data(right)
        return self._human_key(leftData) < self._human_key(rightData)        

class LanTableModel(QStandardItemModel):
    def __init__(self, rows, columns, parent):
        super(LanTableModel, self).__init__(rows, columns, parent)
        QStandardItemModel(0, 2, parent)
        #self._data = data

    def sort(self, column:int, order:Qt.SortOrder=Qt.AscendingOrder ):
        #print( "SORTING",a,b,c,d )
        super(LanTableModel, self).sort(column,order)

    """
    def setHorizontalHeaderLabels(self, labels):
        print( "labels", labels )
    def setRowCount(self,rows:int):
        pass

    def insertRow(self,position:int):
        pass

    def setItem(self, row:int, col:int, item ):
        pass
        


    def data(self, index, role):
        value = None
        key = list(self._data["data"].keys())[index.row()]
        if index.column() == 0:
            value = key
        else:
            value = self._data["data"][key][self._data["columns"][index.column()]]

        if role == Qt.DisplayRole:
            # Get the raw value

            # Perform per-type checks and render accordingly.
            if isinstance(value, datetime):
                # Render time to YYY-MM-DD.
                return value.strftime("%H:%M:%S")

            if isinstance(value, float):
                # Render float to 2 dp
                return "%.2f" % value

            if isinstance(value, str):
                # Render strings with quotes
                return '"%s"' % value

            # Default (anything not captured above: e.g. int)
            return value

        " ""
        if role == Qt.BackgroundRole:
            if (isinstance(value, int) or isinstance(value, float)):
                value = int(value)  # Convert to integer for indexing.

                # Limit to range -5 ... +5, then convert to 0..10
                value = max(-5, value) # values < -5 become -5
                value = min(5, value)  # valaues > +5 become +5
                value = value + 5     # -5 becomes 0, +5 becomes + 10

                return QtGui.QColor(COLORS[value])
        " ""
                
        if role == Qt.TextAlignmentRole:

            if isinstance(value, int) or isinstance(value, float):
                # Align right, vertical middle.
                return Qt.AlignVCenter + Qt.AlignRight

        if role == Qt.ForegroundRole:

            if (
                (isinstance(value, int) or isinstance(value, float))
                and value < 0
            ):
                return QtGui.QColor('red')

        if role == Qt.DecorationRole:
            online = self._data["data"][key]["online"]
            previous = self._data["data"][key]["previous"]

            if index.column() == 0:
                # Just added to the list (no previous state)
                if previous == None:
                    return QtGui.QColor("#0ff" )
                return QtGui.QColor(online and "#0f0" or "#f00" )

            if index.column() == 1:
                if online == previous:
                    " ""
                    pixmap = QtGui.QPixmap(128, 128)
                    pixmap.fill( QtGui.QColor("#0ff" ) )
                    icon = QtGui.QIcon('right.png')
                
                    p = QtGui.QPainter(pixmap)
                    icon.paint(p, QRect( 0,0,128,128 ))
                    p.end()
                    return QtGui.QIcon( pixmap )
                    " ""
                    return QtGui.QIcon('right.png')
                if online:
                    return QtGui.QIcon('up.png')
                else:
                    return QtGui.QIcon('down.png')


            if isinstance(value, datetime):
                return QtGui.QIcon('calendar.png')
            if isinstance(value, bool):
                if value:
                    return QtGui.QIcon('tick.png')

                return QtGui.QIcon('cross.png')
            if (isinstance(value, int) or isinstance(value, float)):
                value = int(value)

                # Limit to range -5 ... +5, then convert to 0..10
                value = max(-5, value)  # values < -5 become -5
                value = min(5, value)   # valaues > +5 become +5
                value = value + 5       # -5 becomes 0, +5 becomes + 10

                return QtGui.QColor(COLORS[value])
                
    def rowCount(self, index):
        # The length of the outer list.
        return len(self._data["data"])

    def columnCount(self, index):
        # The following takes the first sub-list, and returns
        # the length (only works if all rows are an equal length)
        #return len(self._data["data"][list(self._data["data"].keys())[0]])
        return len(self._data["columns"])

    def headerData(self, section, orientation, role):
        # section is the index of the column/row.
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return str(self._data["columns"][section])

            if orientation == Qt.Vertical:
                return None
                #return str(self._data.index[section])
    """
