from werkzeug.security import check_password_hash
import sqlite3

class UserChat:

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    @staticmethod
    def is_authenticated():
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False

    def get_id(self):
        return self.username

    def check_password(self, password_input):
        return check_password_hash(self.password, password_input)

    @staticmethod
    def getRoomDetails(userid):
        global con
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in userchat getRoomDetails function")
        try:
            status = 1
            cur.execute("UPDATE DoctorProfile SET status = ?  WHERE id = ?", (status, userid))

            con.commit()
            print("successfully updated the status value for doctor approval ")
            return 1

        except Exception as e:
            con.rollback()
            print("Error in the updating doctor from profile")
            print(e)





        finally:
            con.close()

        return 0