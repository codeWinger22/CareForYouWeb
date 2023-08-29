

import sqlite3



from flask_login import UserMixin
class User(UserMixin):
    def __init__(self,id,name,email,profile_pic):
        self.id = id
        self.name = name
        self.email = email
        self.profile_pic = profile_pic
        
    
    @staticmethod
    def get(user_id,flag):
        print("flag from get" , flag)
        print(type(user_id))
        print(user_id)
        user = None
        try:
            con = sqlite3.connect("database.db")
           
        
        except:
            print("problem in connecting to database")
       

        try:
            if(flag == 1):
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                cur.execute('SELECT * FROM userAdmin WHERE id = ? ', (user_id, ))
                rows = cur.fetchone()
                if not rows:
                    return None
                else:
                    user = User(id = rows[0],name = rows[1],email = rows[2],profile_pic=rows[3])
                    print("thisis user from get method ",user)


            elif(flag == 2):
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                print(user_id)
                cur.execute('SELECT * FROM userDoctor WHERE id = ? ', (user_id, ))
                rows = cur.fetchone()
                print(rows, "from get doctor")
                if not rows:
                    print("doctor data not found from user")
                    return None
                else:
                    user = User(id = rows[0],name = rows[1],email = rows[2],profile_pic=rows[3])
                    print("thisis user from get method ",user)
            

            elif(flag == 3):
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                cur.execute('SELECT * FROM userPatient WHERE id = ? ', (user_id, ))
                rows = cur.fetchone()
                if not rows:
                    return None
                else:
                    user = User(id = rows[0],name = rows[1],email = rows[2],profile_pic=rows[3])
                    print("thisis user from get method ",user)


            elif(flag == 0):
                count = 0
                try:
                    con.row_factory = sqlite3.Row
                    cur = con.cursor()
                    cur.execute('SELECT * FROM userAdmin WHERE id = ? ', (user_id, ))
                    rows = cur.fetchone()
                    if not rows:
                        count = count +1
                    else:
                        user = User(id = rows[0],name = rows[1],email = rows[2],profile_pic=rows[3])
                        print("thisis user from get method ",user)
                except Exception as e:
                    print(e)
                

                try:
                    con.row_factory = sqlite3.Row
                    cur = con.cursor()
                    cur.execute('SELECT * FROM userDoctor WHERE id = ? ', (user_id, ))
                    rows = cur.fetchone()

                    if not rows:
                        count = count +1
                    else:
                        user = User(id = rows[0],name = rows[1],email = rows[2],profile_pic=rows[3])
                        print("thisis user from get method ",user)
                except Exception as e:
                    print(e)

                try:
                    con.row_factory = sqlite3.Row
                    cur = con.cursor()
                    cur.execute('SELECT * FROM userPatient WHERE id = ? ', (user_id, ))
                    rows = cur.fetchone()
                    if not rows:
                        count = count +1
                    else:
                        user = User(id = rows[0],name = rows[1],email = rows[2],profile_pic=rows[3])
                        print("thisis user from get method ",user)
                except Exception as e:
                    print(e)
                if(count == 3):
                    return None
                else:
                    return user
                    

            


        #user = db.execute("SELECT * FROM user").fetchall()
         
           
        except Exception as e:
            print(e)
        finally:
            con.close()
        
        return user
  
        #user = db.execute("SELECT * FROM user WHERE id = ?",(user_id,)).fetchone()
        #if not user:
         #   return None
        #user = User(id = user[0], name = User[1], email = User[2] , profile_pic= User[3])
        #return user

    @staticmethod
    def create(userid_,name, email, profile_pic,flag):
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in user create function")
        try:
            if(flag ==1):
                cur.execute("INSERT INTO userAdmin (id, name, email, profile_pic) VALUES (?,?,?,?)",(userid_, name, email, profile_pic))
                con.commit()
                print("Record successfully added to database")
            elif(flag == 2):
                cur.execute("INSERT INTO userDoctor (id, name, email, profile_pic) VALUES (?,?,?,?)",(userid_, name, email, profile_pic))
                con.commit()
                print("Record successfully added to database")
            elif(flag == 3):
                cur.execute("INSERT INTO userPatient (id, name, email, profile_pic) VALUES (?,?,?,?)",(userid_, name, email, profile_pic))
                con.commit()
                print("Record successfully added to database")

        except Exception as e:
            con.rollback()
            print("Error in the INSERT")
            print(e)



        finally:
            con.close()


    @staticmethod
    def removePatient(userid):
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in user create function")
        try:
            cur.execute('DELETE FROM userPatient  WHERE id = ? ', (userid,))
            con.commit()
            return 1

        except Exception as e:
            con.rollback()
            print("Error in the Removing Doctor")
            print(e)



        finally:
            con.close()
        return 0

    @staticmethod
    def remove(userid):
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in user create function")
        try:
            cur.execute('DELETE FROM userDoctor  WHERE id = ? ', (userid,))
            con.commit()
            return 1

        except Exception as e:
            con.rollback()
            print("Error in the Removing Doctor")
            print(e)



        finally:
            con.close()
        return 0

        #db =get_db()
        #sql = "INSERT INTO user (id, name,email,profile_pic) VALUES (%s, %s,%s,%s)"
        #val = (id_,name,email,profile_pic)
       #db.execute(sql=sql,val=val )
        #db.commit()



class UserProfile:
    def __init__(self,id,name,email,address,qualification,status):
        self.id= id
        self.name = name
        self.email = email
        self.address = address
        self.qualification = qualification
        self.status = status

    @staticmethod
    def add(userid, name, email, address, qualification, status, flag):
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in user add function")

        try:

             if (flag == 2):
                cur.execute("INSERT INTO DoctorProfile (id, name, email, address,qualification,status) VALUES (?,?,?,?,?,?)",(userid, name, email, address, qualification, status))
                con.commit()
                print("Record successfully added to database")
                if (status == 0):
                    return None
                else:
                    return 1



        except Exception as e:
            con.rollback()
            print("Error in the INSERT")
            print(e)



        finally:
            con.close()

    @staticmethod
    def getDoctorName(doctorid):
        global con
        user = None
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in getDoctorName details")
        try:
            print(doctorid)
            cur.execute('SELECT * FROM DoctorProfile  WHERE id = ? ', (doctorid,))
            rows = cur.fetchone()
            print(rows)
            if not rows:
                return None
            else:
                print(rows[0])
                user = UserProfile(id=rows[0], name=rows[1], email=rows[2], address=rows[3], qualification=rows[4],
                                   status=rows[5])
                print(user)

            print("Record successfully retrieved from  database")
            return user

        except Exception as e:
            con.rollback()
            print("Error in the retriving  doctor name from DoctorProfile table")
            print(e)




        finally:
            con.close()

    @staticmethod
    def getProfile(user_id, flag):
        print("flag from getprofile", flag)
        print(type(user_id))
        print(user_id)
        user = None
        try:
            con = sqlite3.connect("database.db")


        except:
            print("problem in connecting to database")

        try:
            if (flag == 2):
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                cur.execute('SELECT * FROM DoctorProfile WHERE id = ? ', (user_id,))
                rows = cur.fetchone()
                if not rows:
                    print("no profile found")
                    return None
                else:
                    user = UserProfile(id=rows[0], name=rows[1], email=rows[2], address=rows[3],qualification = rows[4],status = rows[5])
                    print("thisis user from getProfile method ", user)
                return user


        except Exception as e:
            con.rollback()
            print("Error in the Fetching from getProfile")
            print(e)



        finally:
            con.close()
        return user


    @staticmethod
    def getApproval():

        rows = None
        try:
            con = sqlite3.connect("database.db")


        except:
            print("problem in connecting to database")

        try:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            status = 0
            cur.execute('SELECT * FROM DoctorProfile WHERE status = ? ', (status,))
            rows = cur.fetchall()
            print(rows,"from getapprove")
            if not rows:
                print("no profile found for admin approval ")
                return None

                    #user = UserProfile(id=rows[0], name=rows[1], email=rows[2], address=rows[3],qualification = rows[4],status = rows[5])
                    #print("thisis user from getProfile method ", user)



        except Exception as e:
            con.rollback()
            print("Error in the Fetching from getApproval")
            print(e)



        finally:
            con.close()
        return rows


    @staticmethod
    def remove(userid):
        user_id  = str(userid)
        print(user_id)
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in userprofile remove function")
        try:
            cur.execute("""
               DELETE FROM DoctorProfile 
               WHERE id = ?
               """, (userid,))

            con.commit()
            cur.execute("SELECT * FROM DoctorProfile")
            rows = cur.fetchall()
            for i in rows:
                print(i)
            print("successfully deleted doctor from table")
            return 1

        except Exception as e:
            con.rollback()
            print("Error in the Removing Doctor from profile")
            print(e)



        finally:
            con.close()

        return 0

    @staticmethod
    def getDoctorData(flag):

        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in userprofile getDoctordata function")
        try:
            if(flag==1):
                #return doctor data
                status = 1
                cur.execute('SELECT * FROM DoctorProfile WHERE status = ? ', (status,))
                rows = cur.fetchall()
                count = 0
                for i in rows:
                    print(i)
                    count = count +1
                print("successfully retrieved doctor from table")
                l = [count , rows]
                return l
            elif(flag == 2):
                cur.execute("SELECT * FROM userPatient")
                rows = cur.fetchall()
                count = 0
                for i in rows:
                    print(i)
                    count = count + 1
                print("successfully retrieved patient from table")
                l = [count,rows]
                return  l

        except Exception as e:
            con.rollback()
            print("Error in the Removing Doctor from profile")
            print(e)

        finally:
            con.close()

        return None

    @staticmethod
    def updateApproval(userid):
        global con
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in userprofile update function")
        try:
            status = 1
            cur.execute("UPDATE DoctorProfile SET status = ?  WHERE id = ?",  (status,userid))

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




class PatientChat:
    def __init__(self, roomid, roomname, doctorid, patientid):
        self.roomid = roomid
        self.roomname = roomname
        self.doctorid = doctorid
        self.patientid = patientid

    @staticmethod
    def getPatientRoom(roomid,roomname, patientid, doctorid):
        global con
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in getPatientRoom details")
        try:

            cur.execute("INSERT INTO roomCred (roomid, roomname, doctorid, patientid) VALUES (?,?,?,?)",
                        (str(roomid), str(roomname), str(doctorid), str(patientid)))
            con.commit()
            print("Record successfully added to database")
            return 1

        except Exception as e:
            con.rollback()
            print("Error in the inserting patient room details in roomCred table")
            print(e)



        finally:
            con.close()

        return 0

    @staticmethod
    def getRoomDetails(roomname):
        global con
        user = None
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in getPatientRoom details")
        try:
            print(roomname)
            cur.execute('SELECT * FROM roomCred WHERE roomname = ? ', (roomname,))
            rows = cur.fetchone()
            print(rows)
            if not rows:
                return None
            else:
                print(rows[0])
                user = PatientChat(roomid=rows[0], roomname=rows[1], doctorid=rows[2], patientid=rows[3])
                print(user)
            print("Record successfully retrieved from  database")
            return user

        except Exception as e:
            con.rollback()
            print("Error in the retriving data in roomCred table")
            print(e)




        finally:
            con.close()

    @staticmethod
    def getPatientRoomName(patientid):
        global con
        user = None
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in getPatientRoomName details")
        try:
            print(patientid)
            cur.execute('SELECT * FROM roomCred WHERE patientid = ? ', (patientid,))
            rows = cur.fetchone()
            print(rows)
            if not rows:
                return None
            else:
                print(rows[0])
                user = PatientChat(roomid=rows[0], roomname=rows[1], doctorid=rows[2], patientid=rows[3])
                print(user)
            print("Record successfully retrieved from  database")
            return user

        except Exception as e:
            con.rollback()
            print("Error in the retriving data from roomCred")
            print(e)




        finally:
            con.close()

    @staticmethod
    def getDoctorRoomName(doctorid):
        global con
        user = None
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in getDoctorRoomName details")
        try:
            print(doctorid)
            cur.execute('SELECT * FROM roomCred WHERE doctorid = ? ', (doctorid,))
            rows = cur.fetchone()
            print(rows)
            if not rows:
                return None
            else:
                print("Record successfully retrieved from  database")
                return rows

            return None

        except Exception as e:
            con.rollback()
            print("Error in the inserting patient room details in roomCred table")
            print(e)




        finally:
            con.close()

    @staticmethod
    def getDoctorChat(doctorid):
        global con
        user = None
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in getDoctorRoomName details")
        try:
            print(doctorid)
            cur.execute('SELECT * FROM roomCred WHERE doctorid = ? ', (doctorid,))
            rows = cur.fetchall()
            print(rows)
            if not rows:
                return None
            else:
                print("Record successfully retrieved from  database")

                return rows

            return None

        except Exception as e:
            con.rollback()
            print("Error in retriving data for doctorchatlist")
            print(e)




        finally:
            con.close()