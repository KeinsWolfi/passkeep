#!/usr/bin/python3
import hashlib
import os
import sys
import shutil
import random
from getpass4 import getpass 		# if getpass not found, try "from getpass4 import getpass"
from tabulate import tabulate
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import customtkinter as tk
import pyperclip as clip

class InfoWindow(tk.CTkToplevel):
	def __init__(self, title, text):
		super().__init__()
		self.title(title)
		self.geometry("250x100")
		self.grid_columnconfigure(0, weight=1)
		self.grid_rowconfigure((0,1), weight=1)
		label = tk.CTkLabel(self, text=text)
		label.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
		button = tk.CTkButton(self, text="OK", command=self.destroy, width=200, height=30)
		button.grid(row=1, column=0, padx=5, pady=5)

def copy_to_clip(text):
	clip.copy(text)

class PasswordManager:
	def __init__(self):
		pass

	def login(self, password):
		try:
			# passowrds database
			db_handle = open("passwords.db", "rb")
			self.path_to_database = "passwords.db"
		except KeyboardInterrupt:
			sys.exit()
		except:
			self.path_to_database = self.check_database_with_pass(password)
			db_handle = open(self.path_to_database, "rb")
		# read decryption key and decrypt database
		self.db_key_hash = db_handle.read(64).decode()
		self.ciphertext = db_handle.read()
		
		self.decryption_key = password
		self.decryption_key = self.pad_db_key(self.decryption_key)
		# calculate SHA-256 sum for the supplied password
		password_hash = hashlib.sha256(self.decryption_key.encode()).hexdigest()
		# check if they match

		if (self.db_key_hash == password_hash):
			db_handle.close()
			self.decrypt_db()
			return True
		else:
			print("\U0000274C Invalid password")
			return False

	def decrypt_db(self):
		# decrypt database with AES-CBC
		if len(self.ciphertext.strip()) != 0:
			aes_instance = AES.new(self.decryption_key.encode(), AES.MODE_CBC, self.decryption_key[:16].encode())
			self.content = unpad(aes_instance.decrypt(self.ciphertext), AES.block_size).decode("UTF-8")
			self.records_count = len(self.content.split("|"))
			print("\U00002714 {} records found".format(self.records_count))
		else:
			self.content = ""
			self.records_count = 0
			print("\U0001F5D1 Database has no records")
		#self.display_options()


	def save_db(self):
		db_handle = open(self.path_to_database, "wb")
		ciphertext = b""
		if self.records_count != 0:
			# encrypt records with AES-CBC
			aes_instance = AES.new(self.decryption_key.encode(), AES.MODE_CBC, self.decryption_key[:16].encode())
			ciphertext = aes_instance.encrypt(pad(self.content.encode(), AES.block_size))
		db_handle.seek(0)
		db_handle.write(self.db_key_hash.encode() + ciphertext)
		db_handle.close()

	def check_database_with_pass(self, password : str):
		print("> 'passwords.db' not found in current path! Drag into here or create new")
		path_to_database = ""
		path_to_database = "/".join(path_to_database.split("/")[:-1])
		if os.path.exists(path_to_database + "/passwords.db"):
			return path_to_database + "/passwords.db"
		elif path_to_database == "":
			path_to_database = "passwords.db"
			db_handle = open(path_to_database, "wb")
			default_pass = hashlib.sha256(self.pad_db_key(password).encode()).hexdigest()
			db_handle.write(default_pass.encode())
			db_handle.close()
			print(f"Created database with decryption key '{password}'! Added a default record")
			return path_to_database
		else:
			print("\U0001F5D1 Database not found")

	def return_credentials(self):
		if self.records_count != 0:
			table = self.content.split("|")
			table = [creds.split("-") for creds in table]
			return table
		else:
			return "Database has no records"

	def add_credential(self, username, password, repeatPassword, platform):
		new_creds = []
		username_or_email = username
		password1 = password
		password2 = repeatPassword
		if password1 != password2:
			print("passwords do not match \U0000274C")
			return False
		platformI = platform
		if self.records_count == 0:
			new_creds.extend([str(1), username_or_email, password1, platformI])
			self.content = "-".join(new_creds)
		else:
			record_id = int(self.content.split("|")[-1].split("-")[0]) + 1
			new_creds.extend([str(record_id), username_or_email, password1, platformI])
			self.content = self.content + "|" + "-".join(new_creds)
		self.records_count += 1
		self.save_db()
		print("Record added \U00002714")
		return True

	def edit_credential(self, record_id, username, password, platform):
		try:
			record_id = int(record_id)
		except:
			print("\U0000274C Invalid record id")
			return False
		if self.records_count != 0:
			record_index = self.find_record(record_id)
			if record_index != None:
				records = self.content.split("|")
				records = [record.split("-") for record in records]
				new_username_or_email = username
				records[record_index][1] = new_username_or_email

				new_password = password
				records[record_index][2] = new_password

				new_platform = platform
				records[record_index][3] = new_platform
				
				records = "|".join(["-".join(record) for record in records])
				self.content = records
				self.save_db()
				print("\U00002714 Record modified")
				return True
			else:
				print("\U0001F5D1 Record id not found")
				return False
		else:
			print("\U0001F5D1 No records to modify")
			return False

	def delete_credential(self, record_id):
		print(record_id)
		try:
			record_id = int(record_id)
		except:
			print("\U0000274C Invalid record id")
			return False
		if self.records_count != 0:
			record_index = self.find_record(record_id)
			if record_index != None:
				new_records = self.content.split("|")
				del new_records[record_index]
				self.records_count -= 1
				if self.records_count == 0:
					self.content = ""
				else:
					self.content = "|".join(new_records)
				self.save_db()
				print("\U00002714 Record deleted")
				return True
			else:
				print("\U0001F5D1 Record id not found")
				return False
		else:
			print("\U0001F5D1 No records to delete")
			return False

	def change_db_password(self, currentPassword, password, confirmPassword):
		current_password = currentPassword
		current_password = self.pad_db_key(current_password)
		current_password_hash = hashlib.sha256(current_password.encode()).hexdigest()
		if current_password_hash != self.db_key_hash:
			print("\U0000274C Current password is incorrect")
			return False
		new_password = password
		if len(new_password) < 10:
			print("\U0000274C Password must be at least 10 characters")
			return False
		confirm_new_password = confirmPassword
		if new_password != confirm_new_password:
			print("\U0000274C Decryption keys do not match")
			return False
		new_password = self.pad_db_key(new_password)
		new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
		self.decryption_key = new_password
		self.db_key_hash = new_password_hash
		self.save_db()
		print(f"\U00002714 Decryption key updated successfully!")
		return True

	def generate_password(self):
		characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+=<>?/.,;:"
		password = "".join(random.choices(list(characters), k = 32))
		return password

	def backup_database(self, password):
		if self.records_count != 0:
			decryption_key = password
			decryption_key_hash = hashlib.sha256(self.pad_db_key(decryption_key).encode()).hexdigest()
			if self.db_key_hash == decryption_key_hash:
				shutil.copyfile(self.path_to_database, "./passwords.db.bak")
				print("\U00002714 Database backup saved in '{}'".format(os.getcwd() + "/passwords.db.bak"))
				return True
			else:
				print("\U0000274C Incorrect database decryption key")
				return False
		else:
			print("\U0001F5D1 No records to backup")
			return False

	def erase_database(self, password):
		if self.records_count != 0:
			decryption_key = password
			decryption_key_hash = hashlib.sha256(self.pad_db_key(decryption_key).encode()).hexdigest()
			if self.db_key_hash == decryption_key_hash:
				self.content = ""
				self.records_count = 0
				self.save_db()
				print("\U00002714 Database erased")
				return True
			else:
				print("\U0000274C Incorrect database decryption key")
				return False
		else:
			print("\U0001F5D1 No records to erase")
			return False

	def pad_db_key(self, password):
		if len(password) % 16 == 0:
			return password
		else:
			return password + ("0" * (16 - (len(password) % 16)))


	def find_record(self, record_id):
		records = self.content.split("|")
		records = [record.split("-") for record in records]
		for i in range(len(records)):
			if int(records[i][0]) == record_id:
				return i
		return None

class App(tk.CTk):
	def __init__(self):
		super().__init__()
		self.width = 1000
		self.height = 800
		self.screen_width = self.winfo_screenwidth()
		self.screen_height = self.winfo_screenheight()
		self.title("PassKeep")
		self.geometry(f"{self.width}x{self.height}")
		self.password_manager = PasswordManager()
		self.create_widgets()
		self.grid_columnconfigure(1, weight = 1)
		self.grid_rowconfigure(0, weight = 1)
		self.entryFrames = []
		self.show_info_windows = True

	def create_widgets(self):
		self.mainFrame = tk.CTkScrollableFrame(self, fg_color="Gray")
		self.mainFrame.grid(row = 0, column = 1, sticky = "nsew", padx = 10, pady = 10)

		self.mainFrame.grid_columnconfigure(0, weight = 1)

		self.buttonFrame = tk.CTkScrollableFrame(self, width=200)
		self.buttonFrame.grid(row = 0, column = 0, sticky = "ns", padx = 10, pady = 10)

		self.buttonFrame.grid_columnconfigure(0, weight = 1)

		self.loginButton = tk.CTkButton(self.buttonFrame, text="Login", command=self.login)
		self.loginButton.grid(row=0, column=0, pady=10, padx=5, sticky="ew")

		self.add_credentialsButton = tk.CTkButton(self.buttonFrame, text="Add credentials", command=self.add_credentials, state="disabled")
		self.add_credentialsButton.grid(row=1, column=0, pady=10, padx=5, sticky="ew")

		self.change_db_passwordButton = tk.CTkButton(self.buttonFrame, text="Change database password", command=self.change_db_password, state="disabled")
		self.change_db_passwordButton.grid(row=2, column=0, pady=10, padx=5, sticky="ew")

		self.backup_db_button = tk.CTkButton(self.buttonFrame, text="Backup database", command=self.backup_database, state="disabled")
		self.backup_db_button.grid(row=3, column=0, pady=10, padx=5, sticky="ew")

		self.erase_db_button = tk.CTkButton(self.buttonFrame, text="Erase database", command=self.erase_database, state="disabled")
		self.erase_db_button.grid(row=4, column=0, pady=10, padx=5, sticky="ew")

		self.settings_button = tk.CTkButton(self.buttonFrame, text="Settings", command=self.show_settings)
		self.settings_button.grid(row=5, column=0, pady=10, padx=5, sticky="ew")

		self.quit_button = tk.CTkButton(self.buttonFrame, text="Quit", command=self.quit)
		self.quit_button.grid(row=6, column=0, pady=10, padx=5, sticky="ew")

	def login(self):
		self.password_input = tk.CTkInputDialog(title="Login", text="Enter decryption key")
		self.logged_in = self.password_manager.login(self.password_input.get_input())

		if self.logged_in:
			self.list_credentials()
			self.loginButton.configure(state="disabled")
			self.add_credentialsButton.configure(state="normal")
			self.change_db_passwordButton.configure(state="normal")
			self.erase_db_button.configure(state="normal")
			self.backup_db_button.configure(state="normal")

	def list_credentials(self):
		for frame in self.entryFrames:
			frame["platform"].grid_forget()
			frame["platform"].destroy()
			frame["username"].grid_forget()
			frame["username"].destroy()
			frame["password"].grid_forget()
			frame["password"].destroy()
			frame["copyButton"].grid_forget()
			frame["copyButton"].destroy()
			frame["frame"].grid_forget()
			frame["frame"].destroy()
		self.entryFrames = []
		entries = self.password_manager.return_credentials()

		if entries == "Database has no records":
			frame = tk.CTkFrame(self.mainFrame)
			frame.grid(row = 1, column = 0, sticky = "ew", pady = 5, padx = 5)

			frame.grid_rowconfigure((0,1,2), weight = 1)
			frame.grid_columnconfigure((0,1,2,3,4,5), weight = 1)

			labelPlatform = tk.CTkLabel(frame, text="Nothing here yet!")
			labelPlatform.grid(row=0, column=0, sticky="ew", columnspan=2, rowspan=3)

			labelUsername = tk.CTkLabel(frame, text="Nothing here yet!")
			labelUsername.grid(row=0, column=2, sticky="ew", columnspan=2, rowspan=3)

			labelPassword = tk.CTkLabel(frame, text="Nothing here yet!")
			labelPassword.grid(row=0, column=4, sticky="ew", columnspan=2, rowspan=3)

			buttonCopy = tk.CTkButton(frame, text="\U0001F4CB", command=lambda passW = "none": copy_to_clip(passW), width=100, state="disabled")
			buttonCopy.grid(row=0, column=6, sticky="ew", pady=2, padx=2)

			buttonDelete = tk.CTkButton(frame, text="\U0000274C", command=lambda entryId = "none": self.delete_credentials(entryId), width=100, state="disabled")
			buttonDelete.grid(row=1, column=6, sticky="ew", pady=2, padx=2)

			buttonEdit = tk.CTkButton(frame, text="\U0000270E", command=lambda entryId = "none": self.edit_credentials(entryId), width=100, state="disabled")
			buttonEdit.grid(row=2, column=6, sticky="ew", pady=2, padx=2)

			self.entryFrames.append({"frame": frame, "platform": labelPlatform, "username": labelUsername, "password": labelPassword, "copyButton": buttonCopy, "editButton": buttonEdit, "deleteButton": buttonDelete})
			return
		for entry in entries:
			frame = tk.CTkFrame(self.mainFrame)
			frame.grid(row = int(entry[0]), column = 0, sticky = "ew", pady = 5, padx = 5)

			frame.grid_rowconfigure((0,1,2), weight = 1)
			frame.grid_columnconfigure((0,1,2,3,4,5), weight = 1)

			labelPlatform = tk.CTkLabel(frame, text=entry[3])
			labelPlatform.grid(row=0, column=0, sticky="ew", columnspan=2, rowspan=3)

			labelUsername = tk.CTkLabel(frame, text=entry[1])
			labelUsername.grid(row=0, column=2, sticky="ew", columnspan=2, rowspan=3)

			labelPassword = tk.CTkLabel(frame, text=entry[2])
			labelPassword.grid(row=0, column=4, sticky="ew", columnspan=2, rowspan=3)

			buttonCopy = tk.CTkButton(frame, text="\U0001F4CB", command=lambda passW = entry[2]: copy_to_clip(passW), width=100)
			buttonCopy.grid(row=0, column=6, sticky="ew", pady=2, padx=2)

			buttonDelete = tk.CTkButton(frame, text="\U0000274C", command=lambda entryId = entry[0]: self.delete_credentials(entryId), width=100)
			buttonDelete.grid(row=1, column=6, sticky="ew", pady=2, padx=2)

			buttonEdit = tk.CTkButton(frame, text="\U0000270E", command=lambda entryId = entry[0]: self.edit_credentials(entryId), width=100)
			buttonEdit.grid(row=2, column=6, sticky="ew", pady=2, padx=2)

			self.entryFrames.append({"frame": frame, "platform": labelPlatform, "username": labelUsername, "password": labelPassword, "copyButton": buttonCopy, "editButton": buttonEdit, "deleteButton": buttonDelete})

	def add_credentials(self):

		topLevel = tk.CTkToplevel(self)
		topLevel.title("Add Credentials")
		topLevel.geometry("600x400")
		topLevel.grid_columnconfigure((0,1,2), weight = 1)
		topLevel.grid_rowconfigure((0,1,2,3), weight = 1)

		entryUsername = tk.CTkEntry(topLevel, placeholder_text="Username/Email")
		entryUsername.grid(row=0, column=0, sticky="ew", padx=5, pady=5, columnspan=3)

		entryPassword = tk.CTkEntry(topLevel, placeholder_text="Password")
		entryPassword.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

		entryRepeatPassword = tk.CTkEntry(topLevel, placeholder_text="Repeat password")
		entryRepeatPassword.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

		buttonRandomPassword = tk.CTkButton(topLevel, text="Generate password", command=lambda: self.generatePassword(entryPassword, entryRepeatPassword))
		buttonRandomPassword.grid(row=1, column=2, sticky="ew", padx=5, pady=5)

		entryPlatform = tk.CTkEntry(topLevel, placeholder_text="Platform")
		entryPlatform.grid(row=2, column=0, sticky="ew", padx=5, pady=5, columnspan=3)

		buttonAdd = tk.CTkButton(topLevel, text="Add", command=lambda: self.add_credentials_to_db(entryUsername.get(), entryPassword.get(), entryRepeatPassword.get(), entryPlatform.get(), topLevel))
		buttonAdd.grid(row=3, column=0, sticky="ew", padx=5, pady=5, columnspan=3)

		topLevel.grab_set()

	def delete_credentials(self, record_id):
		deleted = self.password_manager.delete_credential(record_id)
		self.list_credentials()

		if(deleted):
			if(self.show_info_windows):
				infoWindow = InfoWindow("Success", "Record deleted successfully")
		else:
			if(self.show_info_windows):
				infoWindow = InfoWindow("Error", "Failed to delete record")

	def edit_credentials(self, record_id):
		topLevel = tk.CTkToplevel(self)
		topLevel.title("Add Credentials")
		topLevel.geometry("600x400")
		topLevel.grid_columnconfigure((0,1,2), weight = 1)
		topLevel.grid_rowconfigure((0,1,2,3,4), weight = 1)

		entries = self.password_manager.return_credentials()
		entry = None
		for e in entries:
			if e[0] == record_id:
				entry = e
				break

		labelEdit = tk.CTkLabel(topLevel, text="Edit credentials for " + entry[3])
		labelEdit.grid(row=0, column=0, sticky="ew", padx=5, pady=5, columnspan=3)

		entryUsername = tk.CTkEntry(topLevel, placeholder_text=entry[1])
		entryUsername.grid(row=1, column=0, sticky="ew", padx=5, pady=5, columnspan=3)

		entryPassword = tk.CTkEntry(topLevel, placeholder_text=entry[2])
		entryPassword.grid(row=2, column=0, sticky="ew", padx=5, pady=5, columnspan=2)

		buttonGenerate = tk.CTkButton(topLevel, text="Generate password", command=lambda: self.generatePassword(entryPassword, entryPassword), width=100)
		buttonGenerate.grid(row=2, column=2, sticky="ew", padx=5, pady=5)

		entryPlatform = tk.CTkEntry(topLevel, placeholder_text=entry[3])
		entryPlatform.grid(row=3, column=0, sticky="ew", padx=5, pady=5, columnspan=3)

		buttonAdd = tk.CTkButton(topLevel, text="Confirm", command=lambda: self.edit_credentials_db(record_id, entryUsername.get(), entryPassword.get(), entryPlatform.get(), topLevel, entry))
		buttonAdd.grid(row=4, column=0, sticky="ew", padx=5, pady=5, columnspan=3)

		topLevel.grab_set()

	def add_credentials_to_db(self, username : str, password : str, repeatPassword : str, platform : str, topLevel : tk.CTkToplevel):
		topLevel.grab_release()
		topLevel.destroy()
		if password != repeatPassword:
			print("Passwords do not match")
			return
		added = self.password_manager.add_credential(username, password, repeatPassword, platform)
		self.list_credentials()

		if added:
			if(self.show_info_windows):
				infoWindow = InfoWindow("Success", "Record added successfully")
		else:
			if(self.show_info_windows):
				infoWindow = InfoWindow("Error", "Failed to add record")

	def edit_credentials_db(self, record_id : int, username : str, password : str, platform : str, topLevel : tk.CTkToplevel, entry : list):
		topLevel.grab_release()
		topLevel.destroy()
		if(username == ""):
			username = entry[1]
		if(password == ""):
			password = entry[2]
		if(platform == ""):
			platform = entry[3]
		edit = self.password_manager.edit_credential(record_id, username, password, platform)
		self.list_credentials()

		if edit:
			if(self.show_info_windows):
				infoWindow = InfoWindow("Success", "Record modified successfully")
		else:
			if(self.show_info_windows):
				infoWindow = InfoWindow("Error", "Failed to modify record")

	def change_db_password(self):
		topLevel = tk.CTkToplevel(self)
		topLevel.title("Add Credentials")
		topLevel.geometry("400x400")
		topLevel.grid_columnconfigure(0, weight = 1)
		topLevel.grid_rowconfigure((0,1,2,3), weight = 1)

		labelOldPass = tk.CTkLabel(topLevel, text="Old password")
		labelOldPass.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

		entryOldPass = tk.CTkEntry(topLevel, placeholder_text="Old password")
		entryOldPass.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

		labelNewPassword = tk.CTkLabel(topLevel, text="New Password")
		labelNewPassword.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

		entryNewPassword = tk.CTkEntry(topLevel, placeholder_text="New password")
		entryNewPassword.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

		labelRepeatNewPassword = tk.CTkLabel(topLevel, text="Repeat")
		labelRepeatNewPassword.grid(row=2, column=0, sticky="ew", padx=5, pady=5)

		entryRepeatNewPassword = tk.CTkEntry(topLevel, placeholder_text="Repeat new password")
		entryRepeatNewPassword.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

		buttonAdd = tk.CTkButton(topLevel, text="Confirm", command=lambda: self.change_db_password_db(entryOldPass.get(), entryNewPassword.get(), entryRepeatNewPassword.get(), topLevel))
		buttonAdd.grid(row=3, column=0, sticky="ew", padx=5, pady=5, columnspan=2)

		topLevel.grab_set()

	def change_db_password_db(self, currentPassword : str, password : str, confirmPassword : str, topLevel : tk.CTkToplevel):
		topLevel.grab_release()
		topLevel.destroy()
		self.password_manager.change_db_password(currentPassword, password, confirmPassword)
		self.list_credentials()

	def generatePassword(self, entryPassword : tk.CTkEntry, entryRepeatPassword : tk.CTkEntry):
		password = self.password_manager.generate_password()
		entryPassword.delete(0, len(entryPassword.get()))
		entryPassword.insert(0, password)
		entryRepeatPassword.delete(0, len(entryRepeatPassword.get()))
		entryRepeatPassword.insert(0, password)

	def backup_database(self):
		self.password_input = tk.CTkInputDialog(title="Backup", text="Enter decryption key")
		backup = self.password_manager.backup_database(self.password_input.get_input())

		if(backup):
			if(self.show_info_windows):
				infoWindow = InfoWindow("Success", "Database backed up successfully")
		else:
			if(self.show_info_windows):
				infoWindow = InfoWindow("Error", "Backup failed")

	def erase_database(self):
		self.password_input = tk.CTkInputDialog(title="Erase", text="Enter decryption key")
		self.erased = self.password_manager.erase_database(self.password_input.get_input())

		if self.erased:
			self.list_credentials()
			if(self.show_info_windows):
				infoWindow = InfoWindow("Success", "Database erased successfully")
		else:
			if(self.show_info_windows):
				infoWindow = InfoWindow("Error", "Erase failed")

	def show_settings(self):
		topLevel = tk.CTkToplevel(self)
		topLevel.title("Settings")
		topLevel.geometry("800x600")
		topLevel.grid_columnconfigure(0, weight = 1)
		
		checkShowInfo = tk.CTkCheckBox(topLevel, command=self.show_info_windows_toggle, text="Show info windows")
		
		if self.show_info_windows:
			checkShowInfo.select()

		checkShowInfo.grid(row=0, column=0, sticky="n", padx=5, pady=5)

		buttonClose = tk.CTkButton(topLevel, text="Close", command=topLevel.destroy)
		buttonClose.grid(row=1, column=0, sticky="s", padx=5, pady=5)

		topLevel.grab_set()

	def show_info_windows_toggle(self):
		self.show_info_windows = not self.show_info_windows
		print(self.show_info_windows)

tk.set_default_color_theme("dark-blue")  # Themes: "blue" (standard), "green", "dark-blue"
tk.set_appearance_mode("dark")

app = App()
app.mainloop()