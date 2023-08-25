import sqlite3



#conn.execute('CREATE TABLE if not exists user (name TEXT, addr TEXT, city TEXT, zip TEXT)')
try:
    conn = sqlite3.connect('database.db')
    print("Connected to database successfully")
except:
    print("db already created")

try:
    conn.execute('CREATE TABLE if not exists user (id TEXT PRIMARY KEY ,name TEXT NOT NULL ,email TEXT UNIQUE NOT NULL,profile_pic TEXT NOT NULL)')
    print("Created table successfully!")
except Exception as e:
    print(e)

try:
    conn.execute('CREATE TABLE if not exists userAdmin (id TEXT PRIMARY KEY ,name TEXT NOT NULL ,email TEXT UNIQUE NOT NULL,profile_pic TEXT NOT NULL)')
    print("Created table successfully!")
except Exception as e:
    print(e)

try:
    conn.execute('CREATE TABLE if not exists userDoctor (id TEXT PRIMARY KEY ,name TEXT NOT NULL ,email TEXT UNIQUE NOT NULL,profile_pic TEXT NOT NULL)')
    print("Created table successfully!")
except Exception as e:
    print(e)

try:
    conn.execute('CREATE TABLE if not exists userPatient (id TEXT PRIMARY KEY ,name TEXT NOT NULL ,email TEXT UNIQUE NOT NULL,profile_pic TEXT NOT NULL)')
    print("Created table successfully!")
except Exception as e:
    print(e)




try:
    conn.execute('CREATE TABLE if not exists DoctorProfile (id TEXT PRIMARY KEY ,name TEXT NOT NULL ,email TEXT UNIQUE NOT NULL,Address TEXT NOT NULL,qualification TEXT NOT NULL , status INTEGER NOT NULL)')
    print("Created table successfully!")
except Exception as e:
    print(e)





try:
    conn.execute('CREATE TABLE if not exists PatientProfile (id TEXT PRIMARY KEY ,name TEXT NOT NULL ,email TEXT UNIQUE NOT NULL,address TEXT NOT NULL,status INTEGER NOT NULL)')
    print("Created table successfully!")
except Exception as e:
    print(e)


try:
    user_id ='105062158331384984251'
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    status = 0
    #sql_update_query = """DELETE from DoctorProfile where id = ?"""
    #cur.execute(sql_update_query, (user_id,))
    #conn.commit()
    cur.execute('SELECT * FROM DoctorProfile ')
    rows = cur.fetchall()
    for i in rows:
        print(i['name'])

except Exception as e:
    print(e)


try:
    conn.execute('CREATE TABLE if not exists roomDetails (roomid TEXT PRIMARY KEY ,roomname TEXT NOT NULL ,doctorname TEXT UNIQUE NOT NULL,patientname TEXT NOT NULL)')
    print("Created table successfully  chat!")
except Exception as e:
    print(e)



finally:
    conn.close()
    print("database closed")


#