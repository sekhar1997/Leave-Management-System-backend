from sqlalchemy.schema import Sequence
from sqlalchemy.dialects.postgresql import ENUM


# Create Auto Generated string for Employee
Employee_seq_autoid = Sequence(name='employee_seq_autoid', minvalue=1, maxvalue=9223372036854775807, start=100000,increment=1)
Employee_id_autoid = Sequence(name='employee_id_autoid', minvalue=1, maxvalue=9223372036854775807, start=1,increment=1)

LeaveManagement_id_autoid = Sequence(name='leavemanagement_id_autoid', minvalue=1, maxvalue=9223372036854775807, start=1,increment=1)
LeaveManagement_seq_autoid = Sequence(name='leavemanagement_seq_autoid', minvalue=1, maxvalue=9223372036854775807, start=100000,increment=1)

Holiday_id_autoid = Sequence(name='holiday_id_autoid', minvalue=1, maxvalue=9223372036854775807, start=1,increment=1)



# Enum for employe type
EmployeeTYPE = ENUM('EMPLOYEE', 'ADMIN', name='EmployeeTYPE')

# Enum for employee designation
EmployeeDESIGNATION = ENUM('DEVELOPER', 'SENIOR DEVELOPER', 'MANAGER', name='EmployeeDESIGNATION')

#Enum for leave type
LeaveTYPE = ENUM('SICK', 'MEDICAL','CASUAL', name='LeaveTYPE')

ApprovedSTATUS = ENUM('PENDING', 'ACCEPTED','DENIED', name='ApprovedSTATUS')