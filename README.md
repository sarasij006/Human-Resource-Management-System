Human Resource Management System (HRMS)
A modern Human Resource Management System (HRMS) developed as part of a Hackathon project to simplify and digitize day-to-day HR operations. The system provides secure authentication, employee management, attendance tracking, leave management, payroll management, and role-based access for Admin/HR and Employees.
________________________________________
Project Overview
The Human Resource Management System is designed to automate and streamline organizational HR processes. It provides a secure, user-friendly platform where employees can manage their personal information, attendance, leave requests, and payroll details, while administrators can efficiently manage employees, approvals, attendance records, and salary structures.
________________________________________
Features
Authentication & Authorization
•	Secure Sign Up and Sign In
•	Email verification
•	Password validation
•	Role-based access control
•	Session management
Employee Dashboard
•	View personal profile
•	Attendance overview
•	Leave request management
•	Recent notifications
•	Secure logout
Admin Dashboard
•	Employee management
•	Attendance monitoring
•	Leave approval workflow
•	Employee switching
•	Payroll management
Employee Profile Management
•	View personal information
•	View job details
•	View salary structure
•	Upload/View profile picture
•	Document management
•	Edit limited personal information
Attendance Management
•	Daily attendance
•	Weekly attendance
•	Employee check-in/check-out
•	Attendance status:
o	Present
o	Absent
o	Half-Day
o	Leave
Leave Management
•	Apply for leave
•	Paid Leave
•	Sick Leave
•	Unpaid Leave
•	Calendar-based leave selection
•	Leave remarks
•	Leave status tracking:
o	Pending
o	Approved
o	Rejected
Leave Approval System
•	View all leave requests
•	Approve requests
•	Reject requests
•	Add comments
•	Instant status updates
Payroll Management
Employee
•	View salary details (Read-only)
Admin
•	View payroll records
•	Update salary structure
•	Manage payroll information
•	Ensure payroll accuracy
________________________________________
User Roles
Employee
•	View profile
•	Edit limited profile information
•	Check attendance
•	Check-in / Check-out
•	Apply for leave
•	View leave status
•	View payroll
Admin / HR
•	Manage employees
•	View all attendance
•	Approve or reject leave requests
•	Manage payroll
•	Update employee information
•	Access administrative dashboard
________________________________________
Technology Stack
Backend
•	Python
•	Flask
•	SQLite 
•	SQL Alchemy 
•	Werk Zeug 
•	Bootstrap 
Frontend
•	HTML
•	CSS
•	JavaScript
Database
•	MySQL
Development Tools
•	VS Code
•	GitHub
________________________________________
Project Structure
HRMS/
│
├── instance/
│   ├── hrms_dev.db
│   ├── hrms_dev.db-journal.bak
│   └── hrms_dev.db-journal.recovered
│
├── static/
│   ├── profile_pics/
│   ├── app.js
│   └── style.css
│
├── templates/
│   ├── attendance.html
│   ├── base.html
│   ├── dashboard.html
│   ├── email_reset.html
│   ├── email_verify.html
│   ├── forgot_password.html
│   ├── hr_dashboard.html
│   ├── landing.html
│   ├── leaves.html
│   ├── login.html
│   ├── payroll.html
│   ├── profile.html
│   ├── register.html
│   ├── reset_password.html
│   ├── verify_email.html
│   └── verify_pending.html
│
├── venv/
├── .env
├── .gitignore
├── app.py
├── config.py
└── hrms_dev.db
└── Requirement.txt
________________________________________
Installation
1.	Clone the repository
https://github.com/sarasij006/Human-Resource-Management-System.git
3.	Navigate to the project directory
        
4.	Create a virtual environment
python -m venv venv
5.	Activate the virtual environment
Windows
venv\Scripts\activate
Linux / macOS
source venv/bin/activate
6.	Install dependencies
pip install -r requirements.txt
7.	Configure the MySQL database.
8.	Run the application
python app.py
________________________________________

Screenshots

•	Landing Page











•	Register Page


•	Login Page






•	Employee Dashboard

•	HR/ Admin Console - Employee Directory





•	HR/ Admin Console - Leave Request

•	HR/ Admin Console – Attendance



•	HR /Admin Console Payroll



•	Email Verification (Initiation)





















•	Email Verification Acceptance

________________________________________
Future Enhancements
•	Email notifications
•	Face recognition attendance
•	QR-based attendance
•	Mobile application
•	Performance management
•	Recruitment module
•	Analytics dashboard
•	Multi-company support
________________________________________

