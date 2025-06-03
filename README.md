
# 📡 Communication_LTD - Secure Web Information System

This is a final project for the *Computer Security* course.  
It demonstrates a secure web-based management system for a fictional internet company, **Communication_LTD**, using Python, Flask, and MySQL.

---

## 🔐 Security-Oriented Development – Part A

The system includes:

- ✅ **User Registration**
  - Complex password enforcement (length, upper/lower case, digits, symbols)
  - Password hashing using HMAC + Salt
  - Email association for each user

- 🔁 **Change Password**
  - Requires old password verification
  - Enforces new password complexity

- 🔐 **Login System**
  - Verifies username and hashed password securely
  - Flash messages for invalid login

- 📧 **Forgot Password Flow**
  - Sends a random SHA-1 token to user email
  - Allows access to password reset only after code verification

- 👤 **Dashboard**
  - Displays user info: username, email, join date

---

## 💣 Security Testing – Part B (in unsecure branch)

- 🧪 Stored XSS on dashboard (client insertion)
- 🧪 SQL Injection on login, register, and dashboard insert
- ✅ Patched using parameterized queries and escaping techniques

---

## 🗂️ Project Structure

```
📁 Comunication_LTD/
│
├── Backend
└── app.py                  # Main Flask application
├── .env                   # Environment variables (not uploaded)
├── .env.example           # Template for environment setup
├── README.md              # This file
│
├── Frontend/             # HTML pages (Register, Login, Forgot, etc.)
├── static/                # CSS, images
└── requirements.txt       # All needed packages
```

---

## 🌿 Git Branches

This project includes two Git branches:

- `secure` – the secure version of the system (with mitigations and protections)
- `unsecure` – the vulnerable version, used for demonstrating attacks (SQLi, XSS)

You must run each branch separately to evaluate its behavior:

```bash
# To test secure version
git checkout secure
python app.py

# To test vulnerable version
git checkout unsecure
python app.py
```

---

## 💻 Installation & Setup

### 1. 🔧 Install MySQL

- Download MySQL Installer: https://dev.mysql.com/downloads/installer/
- Run the installer and create a **MySQL Server Instance**
- Make sure to enable:
  - ✅ TCP/IP (default port: 3306)
- When prompted, set your **root password** → example: `MyStrongPass2025!`

### 2. 📦 Clone the project

```bash
git clone https://github.com/youruser/Comunication_LTD.git
cd Comunication_LTD
pip install -r requirements.txt
```

### 3. 🔐 Configure environment

Create a file called `.env` in the root folder and add:

```dotenv
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=MyStrongPass2025!   # your MySQL root password
MYSQL_DB=myappdb
SECRET_KEY=your_flask_secret_key
```

> ⚠️ Never push your `.env` to GitHub. Use this example as a guide.

### 4. 🚀 Run the app

```bash
python app.py
```

Visit: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🖼️ Screenshots (suggested placeholders)

### 🔐 Login Page
> ![Login Screenshot](screenshots/login_page.png)

### 📊 Dashboard
> ![Dashboard Screenshot](screenshots/dashboard.png)



---

## 🧪 Notes for Evaluation

This project fulfills the following secure development requirements:

| Feature | Included |
|--------|----------|
| Secure password storage (HMAC + Salt) | ✅ |
| Password complexity via config | ✅ |
| SHA-1 token-based password reset | ✅ |
| Stored XSS (unsecure branch) | ✅ |
| SQL Injection (unsecure branch) | ✅ |
| Mitigations with escaping and parameterized queries | ✅ |

---

## 👩‍💻 Developed by Ido Rosenfeld, Karina Haimov, Liat Simhayev, Shay yeffet, Lev Kravtsov, Or Dorbin

Holon Institute of Technology – Cyber Security Final Project
