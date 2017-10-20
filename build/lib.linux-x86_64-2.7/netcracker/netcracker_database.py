from sqlite3 import *


class Database():
    def __init__(self, db_name):
        self.db_name = db_name
        self.handle, bool = self.get_db_handle()
        if (self.handle is not None and bool is not False):
            self.cursor = self.get_db_cursor(self.handle)
        else:
            return None

    def get_db_handle(self):
        if (self.db_name is not None):
            handle = connect(str(self.db_name))
            return handle, True
        else:
            return None, False

    def get_db_cursor(self, handle):
        if (handle is not None):
            cursor = handle.cursor()
            return cursor
        else:
            return None

    def create_table(self, table_name, cols):
        if (type(table_name) == str and type(cols) == list and self.handle is not None and self.cursor is not None):
            buff = ""
            for i in cols:
                buff = buff + i + ","
            buff = buff[:-1]
            cols = buff
            SQL = "CREATE TABLE IF NOT EXISTS %s (id INTEGER PRIMARY KEY AUTOINCREMENT, %s)" % (table_name, cols)
            self.cursor.execute(SQL)
            self.handle.commit()
            return True
        else:
            if (self.handle == None):
                print "[Database] Handle is None."
            if (self.cursor == None):
                print "[Database] Cursor is None."
            print "[Database] Error creating table."
            return False

    def insert_row(self, table, data):
        if (type(table) == str and type(data) == list and self.cursor is not None and self.handle is not None):
            buff = ""
            for info in data:
                buff += "'" + info + "',"
            buff = buff[:-1]
            values = buff
            SQL = "INSERT INTO %s VALUES (%s)" % (table, values)
            self.cursor.execute(SQL)
            self.handle.commit()
            return True
        else:
            return False

    def delete_row(self, data):
        if (type(data) == dict and self.handle is not None and self.cursor is not None):
            if (len(data) == 1):
                for i in data:
                    key = i
            for i in data[key]:
                col = i
                value = "'" + str(data[key][i]) + "'"
            SQL = "DELETE FROM %s WHERE %s=%s" % (key, col, value)
            self.cursor.execute(SQL)
            self.handle.commit()
            return True
        else:
            return False

    def update_row(self, data, target):
        if (type(data) == dict and self.handle is not None and self.cursor is not None):
            if (len(data) == 1):
                for i in data:
                    key = i

            for i in data[key]:
                col = i
                value = "'" + str(data[key][i]) + "'"
            target = "'" + str(target) + "'"
            SQL = "UPDATE %s SET %s=%s WHERE %s=%s" % (key, col, value, col, target)
            self.cursor.execute(SQL)
            self.handle.commit()
            return True
        else:
            return False
