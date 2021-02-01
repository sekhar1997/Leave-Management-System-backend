from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import *
#from sqlalchemy.dialects import postgresql
#from datetime import datetime, timedelta
#from sqlalchemy.orm import relationship
#from api.common.util import datetime_to_str, get_date
from .sequence import *
#from settings import DOMAIN
#from flask import url_for


db = SQLAlchemy()

class Employee(db.Model):
    __tablename__ = 'Employee'
    id = db.Column(Integer, Employee_id_autoid, server_default=Employee_id_autoid.next_value(
    ), nullable=False, primary_key=True)
    employeeId = db.Column(VARCHAR(25), unique=True, nullable=False)
    firstName = db.Column(VARCHAR(200))
    lastName = db.Column(VARCHAR(200))
    password = db.Column(VARCHAR(500))
    email = db.Column(VARCHAR(200), nullable=False, unique=True)
    phoneNumber = db.Column(VARCHAR(20))
    joinedDate = db.Column(TIMESTAMP)
    employeeType = db.Column(
        EmployeeTYPE, server_default='EMPLOYEE', default='EMPLOYEE', nullable=False)
    employeeDesignation = db.Column(
        EmployeeDESIGNATION, default='DEVELOPER', nullable=False)

    def __init__(self, request):
        self.firstName = request.get('firstName')
        self.lastName = request.get('lastName')
        self.password = request.get('password')
        self.email = request.get('email').lower()
        self.phoneNumber = request.get('phoneNumber')
        self.joinedDate = request.get('joinedDate')


class LeaveManagement(db.Model):
    __tablename__ = 'LeaveManagement'
    id = db.Column(Integer, LeaveManagement_id_autoid, server_default=LeaveManagement_id_autoid.next_value(
    ), nullable=False, primary_key=True)
    leaveId = db.Column(VARCHAR(25), nullable=False, unique=True)
    employeeId = db.Column(VARCHAR(25), nullable=False)
    fromDate = db.Column(TIMESTAMP)
    toDate = db.Column(TIMESTAMP)
    reason = db.Column(VARCHAR(500), nullable=False)
    leaveType = db.Column(LeaveTYPE, nullable=False)
    approver = db.Column(VARCHAR(200))
    approvedStatus = db.Column(ApprovedSTATUS, nullable=False)

    def __init__(self, request):
        self.employeeId = request.get('employeeId')
        self.fromDate = request.get('fromDate')
        self.toDate = request.get('toDate')
        self.reason = request.get('reason')
        self.leaveType = request.get('leaveType')
        self.approvedStatus = request.get('approvedStatus')
        self.approver = request.get('approver')


class Holiday(db.Model):
     __tablename__ = 'Holiday'
     id = db.Column(Integer, Holiday_id_autoid, server_default=Holiday_id_autoid.next_value(
    ), nullable=False, primary_key=True)
     date = db.Column(TIMESTAMP)
     festivalName = db.Column(VARCHAR(200))
     description = db.Column(VARCHAR(500))
     holidayBanner = db.Column(VARCHAR())


     def __init__(self, request):
        self.date = request.get('date')
        self.festivalName = request.get('festivalName')
        self.description = request.get('description')
        self.holidayBanner = request.get('holidayBanner')
