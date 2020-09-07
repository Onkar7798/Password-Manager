import sqlite3
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ADMIN_PASS = r"YOUR_PASSWORD"  
ADMIN_PASS_ENCODED = ADMIN_PASS.encode()  
salt = b'YOUR_SALT_VALUE' 
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(ADMIN_PASS_ENCODED))  
encrypt_obj = Fernet(key)



def storeDB():
	app = input("Enter name of the Application: ")
	uname = input("Enter the Username/Email ID used: ")
	uname_enc = uname.encode()
	uname = encrypt_obj.encrypt(uname_enc)
	pswd = input("Enter the Password used: ")
	pswd_enc = pswd.encode()
	pswd = encrypt_obj.encrypt(pswd_enc)
	values = (app, uname, pswd)
	connect = sqlite3.connect("P_Words.db")
	c = connect.cursor()
	c.execute("INSERT INTO Pwords VALUES(?, ?, ?)",values)
	print("Entry Added Successfully!")
	connect.commit()
	connect.close()

def getDB():
	app = tuple([input("Enter name of the Application: ")])
	print(app)
	connect = sqlite3.connect("P_Words.db")
	c = connect.cursor()
	for content in c.execute("SELECT * FROM Pwords WHERE Application=?",app):
		print("Application Name: "+content[0])
		uname = encrypt_obj.decrypt(content[1])
		print("Username/Email ID used: "+uname.decode())
		pswd = encrypt_obj.decrypt(content[2])
		print("Password: "+pswd.decode())
	connect.commit()
	connect.close()

def displayDB():
	connect = sqlite3.connect("P_Words.db")
	c = connect.cursor()
	for content in c.execute("SELECT * FROM Pwords"):
		print("App: "+content[0], end='')
		uname = encrypt_obj.decrypt(content[1])
		print(", Username: "+uname.decode(), end='')
		pswd = encrypt_obj.decrypt(content[2])
		print(", Pass: "+pswd.decode())
	connect.commit()
	connect.close()

def deleteDB():
	app = tuple([input("Enter the Application to be Deleted: ")])
	choice = input("Do you really want to delete "+str(list(app))+" ?Y/N")
	connect = sqlite3.connect("P_Words.db")
	c = connect.cursor()
	c.execute("DELETE FROM Pwords WHERE Application=?",app)
	print(str(list(app))+" deleted Successfully!")
	connect.commit()
	connect.close()

def accessDB():
	option = int(input("What would you like to do?\n1.Store new Password\n2.Get Password\n3.Display All\n4.Remove Password\n5.Quit\n"))
	if option == 1:
		storeDB()
	elif option == 2:
		getDB()
	elif option == 3:
		displayDB()
	elif option == 4:
		deleteDB()
	elif option == 5:
		quit()
	else:
		print("Enter valid input")
		accessDB()
	
def main():
	user = input("Enter Master Password: ")
	if user == ADMIN_PASS:
		accessDB()
	else:
		print("Invalid Password")
		main()

main()

#Create Database Table once
# c.execute('''CREATE TABLE Pwords(
# 				Application text,
# 				Username text,
# 				Password text
# 			)''')
# connect.commit()
# connect.close()
