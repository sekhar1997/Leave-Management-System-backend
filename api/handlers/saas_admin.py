#from api.common.aws import create_stack,delete_stack,checkAccount
#from  .commonOperations import *
#from .validate_fields import *
from flask_restplus.errors import abort
#from settings import PATH_TO_SECRET, PORTALISSUER, ISSUER
#from datetime import date
import datetime
#from io import StringIO,BytesIO
# from awsjobs.rollback import s3_client, s3_resource
#from passlib.totp import TOTP, MalformedTokenError, TokenError
#import calendar
#import pyqrcode
#import saftrus_rbac
#import base64
#from dateutil.relativedelta import relativedelta
#from settings import ENABLE_MFA_LOGIN
#from settings import AUTO_STACK_CREATION_ENABLED
#from awsjobs.rollback import checkAccount
from sqlalchemy.sql.expression import or_
import requests
from ..define import api as saas_api
from flask_restplus import fields
from ..database.models import *
from functools import wraps
#from flask import g, request, redirect, url_for





#guardSaaSAdmin = saftrus_rbac.Praetorian()
#TotpFactory = TOTP.using(secrets_path=PATH_TO_SECRET, issuer=PORTALISSUER)
total_leaves = 10

nestedEmployeedata = saas_api.model('nestedEmployeedata', {
    'firstName': fields.String(),
    'lastName': fields.String,
    'password': fields.String(),
    'email': fields.String(),
    'phoneNumber': fields.String(),
    'joinedDate': fields.DateTime(),
    'employeeType': fields.String(),
    'employeeDesignation': fields.String()
})


nestedLeaveRequestData = saas_api.model('nestedLeaveRequestData', {
    'employeeId': fields.String(),
    'fromDate': fields.DateTime,
    'toDate': fields.DateTime(),
    'reason': fields.String(),
    'leaveType': fields.String(),
    'approver': fields.String(),
    'approvedStatus': fields.String()
})

LeaveRequestData = saas_api.model('LeaveRequestData', {
    "result": fields.Nested(nestedLeaveRequestData)
})


nestedHolidayData = saas_api.model('nestedHolidayData', {
    'date': fields.DateTime(),
    'festivalName': fields.String(),
    'description': fields.String(),
    'holidayBanner': fields.String()
})

HolidayData = saas_api.model('HolidayData', {
    "result": fields.Nested(nestedHolidayData)
})


SaasLoginRequest = saas_api.model('SaasLoginRequest', {
    'email': fields.String(required=True, description='email'),
    'password': fields.String(required=True, description='password')
})


nestedloginresponse = saas_api.model("nestedloginresponse",{
    'PendingLeaves': fields.Integer(),
    'AppliedLeaves':fields.Integer(),
    'RemainingLeaves':fields.Integer(),
    'name': fields.String()
})

LoginResponse = saas_api.model('LoginResponse', {
    "result": fields.Nested(nestedloginresponse)
})

'''
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            #return redirect(url_for('login', next=request.url))
            return "user not logged in"
        return f(*args, **kwargs)
    return decorated_function
'''
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged  in' in session:
            return f(*args, **kwargs)
        else:
            return "user not logged in"


def logInUser(request):
    payload = request.json
    username = payload.get('email').lower()
    password = payload.get('password')
    employeeDetails = Employee.query.filter_by(email=username).one_or_none()
    if employeeDetails and password == employeeDetails.password:
        result = {}
        #print(type(employeeDetails.employeeId))
        result["PendingLeaves"] = LeaveManagement.query.filter_by(employeeId=employeeDetails.employeeId,approvedStatus="PENDING").count()
        result["AppliedLeaves"] = LeaveManagement.query.filter_by(employeeId=employeeDetails.employeeId,approvedStatus="ACCEPTED").count() + LeaveManagement.query.filter_by(employeeId=employeeDetails.employeeId,approvedStatus="PENDING").count()
        appliedleaves = LeaveManagement.query.filter_by(employeeId=employeeDetails.employeeId,approvedStatus="ACCEPTED").count() + LeaveManagement.query.filter_by(employeeId=employeeDetails.employeeId,approvedStatus="PENDING").count()
        result["RemainingLeaves"] = total_leaves - appliedleaves
        result["name"] = employeeDetails.firstName + " " + employeeDetails.lastName
        result['employeeid'] = employeeDetails.employeeId
        result['employeeType'] = employeeDetails.employeeType
        return {
                   "result": result
                }, 200
    else:
        return abort(400, "User not found.")

def appliedLeaves(employeeId):
    result = LeaveManagement.query.filter_by(employeeId=employeeId).all()
    return {
                   "result": result
                }, 200

def leavesToApprove(username):
    stats = LeaveManagement.query.filter_by(approver=username,approvedStatus="PENDING").all()
    return {
                   "result": stats
                }, 200

#@login_required
def holidayList():
    holidayslist = Holiday.query.all()
    return {
                   "result": holidayslist
                }, 200

def raiseLeaveRequest(payload):
    #payload = request.json
    result = LeaveManagement(payload)
    db.session.add(result)
    safeCommit()
    return {
                   "result": {"Message":"succesfully raised your leave request"}
                }, 200

def addEmployee(payload):
    result = Employee(payload)
    db.session.add(result)
    safeCommit()
    return {
                   "result": {"Message":"employee added successfully"}
                }, 200


def approveLeave(leaveId,status):
    result = LeaveManagement.query.filter_by(leaveId=leaveId).one_or_none()
    if result:
        result.approvedStatus = status
        db.session.add(result)
        safeCommit()
    return {
                   "result": {"Message":"succesfully updated the approved status"}
                }, 200


def addHoliday(payload):
    # print("payload:",payload)
    result = Holiday(payload)
    db.session.add(result)
    safeCommit()
    return {
                   "result": {"Message":"succesfully added holiday"}
                }, 200

def leavesCount(empid):
    print(type(empid))
    result = {}
    result["PendingLeaves"] = LeaveManagement.query.filter_by(employeeId=empid,approvedStatus="PENDING").count()
    result["AppliedLeaves"] = LeaveManagement.query.filter_by(employeeId=empid,approvedStatus="ACCEPTED").count() + LeaveManagement.query.filter_by(employeeId=empid,approvedStatus="PENDING").count()
    appliedleaves = LeaveManagement.query.filter_by(employeeId=empid,approvedStatus="ACCEPTED").count() + LeaveManagement.query.filter_by(employeeId=empid,approvedStatus="PENDING").count()
    result["RemainingLeaves"] = total_leaves - appliedleaves
    return {
                   "result": result
                }, 200


def upcomingHoliday():
    result = Holiday.query.order_by(Holiday.date).all()
    today = datetime.date.today()
    print("today::", today)
    for holiday in result:
        if (today - holiday.date.date()).days <0:
            return {
                   "result": holiday
                }, 200


def safeCommit():
    try:
        db.session.commit()
    except:
        db.session.rollback()
        raise


























'''
def parse_input_datetime(s):
    return datetime.strptime(s,'%Y-%m-%dT%H:%M:%S.%fZ')

'''


'''
def safeCommit_notifications(record):
    try:
        db.session.add(record)
        db.session.commit()
    except:
        db.session.rollback()
        raise


def get_month_day_range(monthParam):
    
    #https://gist.github.com/waynemoore/1109153
    
    date = datetime.strptime(monthParam+"T23:59:59",'%m-%YT%H:%M:%S')
    first_day = date.replace(day = 1)
    last_day = date.replace(day = calendar.monthrange(date.year, date.month)[1])
    return first_day, last_day


PortalAdminRecord = saas_api.model('PortalAdminRecord',{
    'portalAdminId': fields.String(required = False, description = 'portalAdmin ID'),
    'firstName': fields.String(required=True, description='firstName'),
    'lastName': fields.String(required=True,description='lastname'),
    'email': fields.String(required=True,description='email'),
    'phoneNumber': fields.String(required=False,description='phone number'),
    'modifiedOn': fields.DateTime,
    'portalLogin': fields.String(required=False,description='portal login')
})

PortalAdminPost = saas_api.clone('PortalAdmin Post', PortalAdminRecord)
del PortalAdminPost['portalAdminId']
del PortalAdminPost['modifiedOn']
del PortalAdminPost['portalLogin']

PortalAdminPut = saas_api.clone('PortalAdmin Put', PortalAdminPost)
del PortalAdminPut['email']

PortalAdminResponse = saas_api.clone('PortalAdminResponse List', {
    'result': fields.Nested(PortalAdminRecord)
})


AccountRecord = saas_api.model('AccountRecord', {
    'accountId': fields.String(rquired=False,description='Account ID'),
    'accountName': fields.String(required=True, description='AccountName'),
    'accountStatus': fields.String(required=False, description='accountStatus', enum=['ACTIVE', 'INACTIVE', 'NOT CREATED', 'DELETE IN PROGRESS']),
    'accountSubDomain': fields.String(required=True, description='accountSubDomain'),
    'pocName': fields.String(required=True, description='pocName'),
    'pocEmail': fields.String(required=True, description='pocEmail'),
    'profileId': fields.String(required=False, description='billing profile ID'),
    'pocPhone': fields.String(required=True, description='pocPhone'),
    'modifiedOn': fields.DateTime,
    'createdOn': fields.DateTime,
    'billingAddress': fields.String(required=True, description='billing address'),
    'pocCity': fields.String(required=True, description='City'),
    'pocState': fields.String(required=True, description='State'),
    'pocZipCode': fields.String(required=True, description='zip code'),
    'pocCountry': fields.String(required=True, description='Country'),
    'supportTier': fields.String(required=False, description='accounts support tiers', enum=['STANDARD TIER', 'SILVER TIER', 'GOLD TIER', 'PLATINUM TIER']),
    'billingEmailAddress': fields.String(required=True, description='email address to send reciepts of billing payment info'),
    'sendInvoice': fields.Boolean(required=True),
    'isSuspended': fields.Boolean(required=False)
})

AccountRecordResponse = saas_api.clone('AccountRecordResponse', {
    'result': fields.Nested(AccountRecord)
})

AccountRecordPost = saas_api.clone('Account Post', AccountRecord)
del AccountRecordPost['accountId']
del AccountRecordPost['accountStatus']
del AccountRecordPost['modifiedOn']
del AccountRecordPost['createdOn']
del AccountRecordPost['isSuspended']

AccountRecordPut = saas_api.clone('Account Put', AccountRecordPost, {
    'profileId': fields.String(required=True, description='billing profile ID'),
    'supportTier': fields.String(required=True, description='accounts support tiers', enum=['STANDARD TIER', 'SILVER TIER', 'GOLD TIER', 'PLATINUM TIER'])
    })
del AccountRecordPut['accountSubDomain']

OTP = saas_api.model('OneTimePassword', {
    'adminId': fields.String(),
    'adminOTP': fields.String()
})

AccountAdministratorRecord = saas_api.model('AccountAdmin List', {
    'adminId': fields.String(required=False,description='adminId'),
    'accountId': fields.String(required=True,description='accountId'),
    'adminName': fields.String(required=True, description='adminName'),
    'adminEmail': fields.String(required=True, description='adminEmail'),
    'adminPhone': fields.String(required=True, description='adminPhone'),
    'adminLastAccess': fields.DateTime,
    'modifiedOn': fields.DateTime
})

AccountAdministratorRecordPost = saas_api.clone('AccountAdmin Post',AccountAdministratorRecord,{
    'adminOTP': fields.String(required=False, description='admin OTP')
})
del AccountAdministratorRecordPost['adminId']
del AccountAdministratorRecordPost['accountId']
del AccountAdministratorRecordPost['adminLastAccess']
del AccountAdministratorRecordPost['modifiedOn']

AccountAdministratorRecordPut = saas_api.clone('AccountAdmin Put',AccountAdministratorRecordPost)
del AccountAdministratorRecordPut['adminEmail']
del AccountAdministratorRecordPut['adminOTP']

AccountAdministratorRecordResponse = saas_api.clone('AccountAdministratorRecordResponse', {
    'result': fields.List(fields.Nested(AccountAdministratorRecord))
})

AccountBillingRecord = saas_api.model('AccountBilling List', {
    'billingId': fields.String(required=False,description='billing Id'),
    'accountId':fields.String(required=True,description='accountId'),
    'billingAmount': fields.Integer(required=False, description='Billing Amount'),
    'billingDate': fields.DateTime,
    'paymentDueDate': fields.DateTime,
    'paymentDate': fields.DateTime,
    'paymentId': fields.String,
    'deactivationDate': fields.DateTime,
    'notifyFrequency': fields.String(required=False,description='frequency'),
    'suspensionDate': fields.DateTime,
    'paymentMade': fields.Boolean(required=False, description='indicates payment has been done or not'),
    'paymentVerification': fields.String(required=False, description='name of the saas admin who verified the payment')
})

AccountBillingRecordResponse = saas_api.clone('AccountBillingRecordResponse', {
    'result': fields.List(fields.Nested(AccountBillingRecord))
})

AccountBillingRecordPut = saas_api.model('AccountBilling Put',AccountBillingRecord)
del AccountBillingRecordPut['billingId']
del AccountBillingRecordPut['billingAmount']
del AccountBillingRecordPut['billingDate']
del AccountBillingRecordPut['paymentDate']
del AccountBillingRecordPut['paymentId']
del AccountBillingRecordPut['accountId']
del AccountBillingRecordPut['deactivationDate']
del AccountBillingRecordPut['paymentMade']
del AccountBillingRecordPut['paymentVerification']

AccountUsageRecord = saas_api.model('AccountUsage List',{
    'usageId': fields.String(required=False,description='usage ID'),
    'usageDate': fields.DateTime,
    'totalUsers': fields.Integer(required=False, description='totalUsers'),
    'activeUsers': fields.Integer(required=False, description='totalUsers'),
    'accountId': fields.String(required=False, description='accountID'),
    'activeDevices':fields.Integer(required=False, description='activeDevices')
})

AccountUsageRecordResponse = saas_api.model('AccountUsageRecordResponse', {
    "result": fields.Nested(AccountUsageRecord)
})

AccountUsageRecordRequest = saas_api.model('AccountUsage ListMonth', {
    'month': fields.String(required=True,description='month')
})

CheckEmail = saas_api.model('CheckEmail', {
    'rounds': fields.Integer(required=True, description='rounds'),
    'salt': fields.String(required=True, description='salt')
})

CheckEmailRequest = saas_api.model('CheckEmailRequest', {
    'email': fields.String(required=True, description='email id')
})

CheckEmailResponse = saas_api.model('CheckEmailResponse',{
    "result": fields.Nested(CheckEmail)
})

LoginRequest = saas_api.clone('LoginRequest', CheckEmailRequest, {
    'password': fields.String(required=True, description='password'),
    'domain': fields.String(required=True, description='account subdomain'),
    'token': fields.String(required=True, description='one time password')
})

SaasLoginRequest = saas_api.clone('SaasLoginRequest', CheckEmailRequest, {
    'password': fields.String(required=True, description='password'),
    'token': fields.String(required=True, description='one time password')
})

SaasInitialLoginRequest = saas_api.model('SaasInitialLoginRequest', {
    'email': fields.String(required=True, description='emailid'),
    'password': fields.String(required=True, description='password')
})

SaaSInitialLoginResponse = saas_api.model('SaaSInitialLoginResponse', {
    "message": fields.String(description="response message"),
    "totp": fields.String(description="secret token if generated")
})

LoginRecord = saas_api.model('Login', {
    'access_token': fields.String(required=True,description='JWT Access token'),
    'name': fields.String(required=True, description='Name of the user'),
    'email': fields.String(required=True, description='Email of the user'),
    'key_gen_pending': fields.Boolean(required=False, default=False),
    'registrationId': fields.String(required=False),
    'isSuspended': fields.Boolean(required=False, description='indicates whether the account is suspended or not')
})

LoginResponse = saas_api.model('LoginResponse',{
    "result": fields.Nested(LoginRecord)
})

SaaSAccountUpdateRequest = saas_api.model('AccountUpdate request',{
    'password':fields.String(required=True, description='existing password'),
    'new_password':fields.String(required=True, description='new password'),
    'token': fields.String(required=True, decription='token')
})

SaaSAdminTokenRefresh = saas_api.model('EnterpriseTokenRefresh',{
    'refresh_token': fields.String(required=True,description='refresh token')
})

SaaSAdminTokenRefreshResponse = saas_api.clone('SaaSAdminTokenRefreshResponse', {
    'result': fields.Nested(SaaSAdminTokenRefresh)
})

BillingTiersRecord = saas_api.model('BillingTiersRecord', {
    'tierId': fields.String(required=False,description='tier ID'),
    'tierName': fields.String(required=True,description='tierName'),
    'userUpperLimit': fields.Integer(required=False,description='user upper limit'),
    'userLowerLimit': fields.Integer(required=True,description='user lower limit'),
    'userCost': fields.Integer(required=True,description='user cost'),
})

BillingTiersPost = saas_api.clone('BillingTiers Post', BillingTiersRecord)
del BillingTiersPost['tierId']
del BillingTiersPost['tierName']
del BillingTiersPost['userLowerLimit']

BillingTiersResponse = saas_api.clone('BillingTiersResponse', {
    'result': fields.List(fields.Nested(BillingTiersRecord))
})

OTPRecord = saas_api.model('OTPRecord',{
    'adminOTP': fields.String(required=False, description= 'admin OTP'),
    'adminOTPExpiryDate': fields.DateTime,
    'Valid': fields.Boolean
})

OTPResponse = saas_api.clone('OTP Response', {
    'result': fields.Nested(OTPRecord)
})

OTPPost = saas_api.clone('OTPPost',{
    'adminOTP': fields.String(required=False, description= 'admin OTP')
})

RegistrationRequest = saas_api.model('RegistrationRequest POST', {
    'email': fields.String(required=True, description='email'),
    'otp': fields.String(required=True, description='one time password'),
    'reset': fields.Boolean(required=False, description='true to represent forget password stage')
})

RegistrationQRImageRequest = saas_api.model('RegistrationQRImageRequest POST',{
    'registrationId': fields.String(required=True, description='registration ID')
})

RegistrationVerifyRequest = saas_api.model('RegistrationVerifyRequest POST',{
    'token1': fields.String(required=True, description='token1'),
    'token2': fields.String(required=True, description='token2'),
    'password': fields.String(required=True, description='password'),
    'registrationId': fields.String(required=True, description='registration ID')
})

CurrentSaasAdminInfo = saas_api.model('CurrentSaasAdminInfo',{
    'portalAdminId': fields.String(),
    'firstName': fields.String(),
    'lastName': fields.String(),
    'email': fields.String(),
    'phoneNumber': fields.String(),
    'lastAccess': fields.DateTime(),
    'createdOn': fields.DateTime()
})

CurrentSaasAdminInfoResponse = saas_api.model('CurrentSaasAdminInfoResponse',{
    'result': fields.Nested(CurrentSaasAdminInfo)
})

BillingProfileRecord = saas_api.model('BillingProfileRecord', {
    'profileId': fields.String(required=False,description='profileId'),
    'billingProfileName': fields.String(required=True, description='billing profile name'),
    'frequency': fields.String(required=True, description='frequency'),
    'createdOn': fields.DateTime,
    'modifiedOn': fields.DateTime
})

BillingProfileResponse = saas_api.model('BillingProfileResponse', {
    'result': fields.List(fields.Nested(BillingProfileRecord))
})

BillingProfilePost = saas_api.clone('BillingProfilePost', BillingProfileRecord)
del BillingProfilePost['profileId']
del BillingProfilePost['createdOn']
del BillingProfilePost['modifiedOn']

InvoicePost = saas_api.clone('InvoicePost', {
    'accountId': fields.String(required=True, description="account Id of the enterprise account")
})

UpgradeRecord = saas_api.model('UpgradeRecord',{
    'upgradeId': fields.String(required=True, description='upgrade id'),
    'package': fields.String(required=True, description = 'upgradepackage file'),
    'releaseNotes': fields.String(required=True, description='release notes for the upgrade package'),
    'supportedVersions': fields.List( fields.String, required=True, description='list of supported versions'),
    'packageInformation': fields.String(required=False, description="Version + description"),
    'upgradeStatus': fields.String(required=True, description='upgrade status'),
    'checkSum': fields.String(required=True, description='checksum of the upgrade')
})


UpgradeResponse = saas_api.model('UpgradeResponse',{
    'result': fields.List(fields.Nested(UpgradeRecord))
})


UpgradeRequest = saas_api.clone('UpgradeRequest', {
    # 'filename': fields.String(required=True, description='file name'),
    'package': fields.String(required=True, description = 'upgradepackage file'),
    'releaseNotes': fields.String(required=True, description='release notes for the upgrade package'),
    'supportedVersions': fields.List( fields.String, required=True, description='list of supported versions'),
    'description': fields.String(required=True, description='description of the package'),
    'version': fields.String(required=True, description='version'),
    'checkSum': fields.String(required=True, description='checksum of the upgrade')
})


Version = saas_api.model('Version', {
    'version': fields.String(description="version string")
})

VersionsResponse = saas_api.model('VersionsResponse',{
    'result': fields.List(fields.Nested(Version))
})

BillingProfileModifyRecord = saas_api.model('BillingProfileModifyRecord', {
    'profileId': fields.String(required=False,description='profileId')
})

BillingTierModifyRecord = saas_api.model('BillingTierModifyRecord', {
    'tierId': fields.String(required=False,description='tierId')
})

DashboardRecord = saas_api.model('DashboardRecord',{
    'numberOfAccounts': fields.Integer(),
    'numberOfUsers':fields.Integer(),
    'numberOfDevices':fields.Integer()
})


DashboardResponse = saas_api.clone('DashboardResponse',{
    'result': fields.Nested(DashboardRecord)
})


HaRepoInfoRecordPost = saas_api.model('HaRepoInfoRecordPost', {
    'clusterAdress': fields.String(),
    'clusterSecretKey': fields.String(),
    'repoAccountId': fields.Integer,
    'repoAddress': fields.String(),
    'repoPeerId': fields.String(),
    'repoConfig': fields.String(),
    # 'userId': fields.String(),
    # 'repoUserConfig': fields.String(),
})

Stats = saas_api.model('Stats', {
    'clusterAdress': fields.String(),
    'clusterSecretKey': fields.String(),
    'repoAccountId': fields.Integer,
    'repoAddress': fields.String(),
    'repoPeerId': fields.String(),
    'repoConfig': fields.String(),
    # 'userId': fields.String(),
    # 'repoUserConfig': fields.String(),
})



def createAccountRecords(payload):
    validations = dict()
    if not validate_name(payload.get('accountName')):
        validations['accountName'] = "account name should be a proper name"
    if not validate_subdomain(payload.get('accountSubDomain')):
        validations['accountSubDomain'] = "account subdomain should be a proper name"
    if not validate_name(payload.get('pocName')):
        validations['pocName'] = "poc name should be a proper name"
    if not validate_email(payload.get('pocEmail')):
        validations['pocEmail'] = "email is required!"
    if not validate_phonenumber(payload.get('pocPhone')):
        validations['pocPhone'] = "Please enter a phone number as ten digits without spaces, e.g.:  1234567890"
    if not validate_CityCountryNames(payload.get('pocCity')):
        validations['pocCity'] = "City name should be a valid city name"
    if not validate_zipcode(payload.get('pocZipCode')):
        validations['pocZipCode'] = "Zip code should be a proper zip code"
    if not validate_CityCountryNames(payload.get('pocState')):
        validations['pocState'] = "State name should be a valid state name"
    if not validate_email(payload.get('billingEmailAddress')):
        validations['billingEmailAddress'] = "Billing email is required!"
    if validations:
        abort(400, "Cannot create account.", errors = validations)
    account_exists = checkAccount(payload.get('accountSubDomain'))
    if account_exists:
        abort(400, "Cannot create account.", errors = {"accountSubDomain": "accountSubDomain already exists"})
    #create account record in database
    r = Account(payload)
    subdomain = payload.get('accountSubDomain')
    error_list = dict()
    if not validate_unique_key(Account, Account.accountSubDomain, r.accountSubDomain):
        error_list['accountSubDomain'] = "subDomain already exists"
    if error_list:
        print("duplicate data found..... :(")
        abort(400, "Cannot create account.", errors = error_list)
    else:
        db.session.add(r)
        try:
            safeCommit()
        except Exception as e:
            print(str(e))
            abort(500, "Cannot create account.", errors = {"message": "Cannot save account record" })
        try:
            payload['adminName'] = payload.pop('pocName')
            payload['adminEmail'] = payload.pop('pocEmail').lower()
            payload['adminPhone'] = payload.pop('pocPhone')
            print(payload)
            createAccountAdminRecords(payload,r.accountId)
        except Exception as e:
            print(str(e))
            abort(400, "Account created but could not create default admin account for this enterprise account.")

    if AUTO_STACK_CREATION_ENABLED:
        try:
            print("subdomain name is "+subdomain)
            stackid = create_stack(subdomain)
            r.stackId = stackid
            db.session.add(r)
            safeCommit()
        except Exception as e:
            print(str(e))
            abort(400, "Unable to create cloud stack.")
    return {
        "result": {"message": " Successfully added customer account record."}
        }, 201


def getAllAccountRecords():
    qryRes = Account\
                  .query\
                .filter(Account.deletedOn == None) \
                  .all()

    return {
        "result": qryRes,
    }, 200


def updateSingleAccountRecords(request, accountId):
    qryRes = Account\
          .query\
          .filter_by(accountId=accountId)\
          .all()
    if qryRes:
        payload = request.json
        validations = dict()
        try:
            toupdate = qryRes[0]
            validations = dict()
            if 'accountName' in request.json:
                if not validate_name(request.json['accountName']):
                    validations['accountName'] = "account name should be a proper name"
                else:
                    toupdate.accountName = request.json['accountName']
            if 'pocName' in request.json:
                if not validate_name(request.json['pocName']):
                    validations['pocName'] = "poc name should be a proper name"
                else:
                    toupdate.pocName = request.json['pocName']
            if 'pocEmail' in request.json:
                if not validate_email(request.json['pocEmail']):
                    validations['pocEmail'] = "poc email should be a proper email"
                else:
                    toupdate.pocEmail = request.json['pocEmail'].lower()
            if 'pocPhone' in request.json:
                if not validate_phonenumber(request.json['pocPhone']):
                    validations['pocPhone'] = "poc phone should be a proper phone number"
                else:
                    toupdate.pocPhone = request.json['pocPhone']
            if 'profileId' in request.json:
                toupdate.profileId = request.json['profileId']
            if 'billingAddress' in request.json:
                toupdate.billingAddress = request.json['billingAddress']
            if 'pocCity' in request.json:
                if not validate_CityCountryNames(request.json['pocCity']):
                    validations['pocCity'] = "City name should be a valid city name"
                toupdate.pocCity = request.json['pocCity']
            if 'pocState' in request.json:
                if not validate_CityCountryNames(request.json['pocState']):
                    validations['pocState'] = "State name should be a valid state name"
                toupdate.pocState = request.json['pocState']
            if 'pocZipCode' in request.json:
                if not validate_zipcode(request.json['pocZipCode']):
                    validations['pocZipCode'] = "Zip code should be a proper zip code"
                toupdate.pocZipCode = request.json['pocZipCode']
            if not validate_email(request.json['billingEmailAddress']):
                validations['billingEmailAddress'] = "billing email address should be a proper email"
            toupdate.billingEmailAddress = request.json['billingEmailAddress'].lower()
            toupdate.pocCountry = request.json['pocCountry']
            toupdate.supportTier = request.json['supportTier']
            toupdate.sendInvoice = request.json['sendInvoice']

            if validations:
                abort(400, "Cannot update account.", errors=validations)
            db.session.add(toupdate)
            safeCommit()
            return {
                "result": {"message": "Successfully updated organisation account record."}
            }, 201

        except Exception as e:
            abort(400, "Cannot update account.", errors=validations)
    else:
        abort(400, "No organisation record found.")


def getSingleAccountRecords(request, accountId):
    qryRes = Account\
                  .query\
                  .filter_by(accountId=accountId)\
                  .all()

    if qryRes:
        return {
                   "result": qryRes[0]
                 }, 200

    else:
        abort(400, "Account not found.")


def deleteSingleAccountRecords(request, accountId):
    qryRes = Account.query.filter_by(accountId=accountId).all()
    print(qryRes,accountId)
    if qryRes:
        if qryRes[0].accountStatus != "DELETE IN PROGRESS":
            if qryRes[0].stackId is not None:
                response = delete_stack(qryRes[0].stackId)
                qryRes[0].accountStatus = "DELETE IN PROGRESS"
                db.session.add(qryRes[0])
                try:
                    safeCommit()
                except Exception as e:
                    print(str(e))
                    abort(400,"unable to delete")
                if qryRes[0].accountStatus == "DELETE IN PROGRESS":
                #if delete_record(Account, Account.accountId, accountId):
                    return {
                        "result": {"message": "Organisation account record deletion is in progress."}
                        }, 200
                else:
                    abort(400, "Unable to delete organisation record.")
            else:
                delete_record(Account, Account.accountId, accountId)
                return{
                    "result": {"message": "Organisation account record deleted successfully."}
                },200
    else:
        abort(400, "No organisation record found.")


########### Account Admin #######


def createAccountAdminRecords(payload, accountId):
    validations = dict()
    if not validate_name(payload.get('adminName')):
        validations['adminName'] = "admin name should be a proper "
    if not validate_email(payload.get('adminEmail')):
        validations['email'] = "email is required!"
    if payload.get('adminPhone') == "":
        validations['adminPhone'] = " admin phone should be a proper phone number"
    if not validate_phonenumber(payload.get('adminPhone')):
        validations['adminPhone'] = "admin phone should be a proper phone number"
    if validations:
        abort(400, "Cannot create admin.", errors = validations)
    r = AccountAdministrator(accountId, payload)
    error_list = dict()
    if not validate_unique_key_admin(AccountAdministrator, AccountAdministrator.adminEmail, AccountAdministrator.accountId, accountId, r.adminEmail):
        error_list['email'] = "email id already exists for this organization"
    if error_list:
        abort(400, "Cannot create admin account, email id already exists for this organization.", errors=error_list)
    else:
        try:
            db.session.add(r)
            safeCommit()
            otp = payload.get('adminOTP')
            if otp is None:
                otp = generate_random()
            o = OneTimePassword(r.adminId, otp)
            db.session.add(o)
            safeCommit()

            # Send email
            account = Account.query.filter_by(accountId=r.accountId).one()

            if account.accountStatus == 'ACTIVE':
                template = "email/admin-account-registration.html"
            else:
                template = "email/account-registration.html"

            billingProfile = AccountBillingProfile.query.filter_by(profileId=account.profileId).one()
            tiers = BillingTiers.query.filter_by(profileId=account.profileId).order_by(BillingTiers.userUpperLimit).all()
            print(tiers)
            context = MailContext(name=r.adminName,
                                  account_name=account.accountName,
                                  account_url="https://" + account.accountSubDomain,
                                  activate="https://"+account.accountSubDomain+"/#/enterprise-activation",
                                  email=r.adminEmail,
                                  otp=otp,
                                  billing_plan=billingProfile.frequency,
                                  tiers=tiers,
                                  support_plan=account.supportTier,
                                  send_invoice=account.sendInvoice,
                                  )
            send_email(template_file=template,
                       subject="Verify your CyDrive account",
                       recipients=[r.adminEmail],
                       context=context)
            return {
                "result": {"message": "Successfully added organization account administrator."}
                }, 201

        except Exception as e:
            print(str(e))
            abort(400, "cannot create account")


def getAllAccountAdminRecords(request, accountId):
    qryRes = AccountAdministrator.query.filter(and_(AccountAdministrator.accountId==accountId, AccountAdministrator.adminName != None, AccountAdministrator.deletedOn == None)).all()

    return {
               "result": qryRes,
            }, 200


########### Single Account Admin #######


def updateSingleAccountAdminRecords(request, accountId, adminId):
    qryRes = AccountAdministrator\
                  .query\
                  .filter_by(accountId=accountId)\
                  .filter_by(adminId=adminId)\
                  .all()

    if qryRes:
        toupdate = qryRes[0]
        validations = dict()
        if 'adminName' in request.json:
            if not validate_name(request.json['adminName']):
                validations['adminName'] = "admin name should be a proper name"
            toupdate.adminName = request.json['adminName']
        if request.json['adminPhone'] == "":
            validations['adminPhone'] = " admin phone should be a proper phone number"
        if 'adminPhone' in request.json:
            if not validate_phonenumber(request.json['adminPhone']):
                validations['adminPhone'] = "admin phone should be a proper phone number"
            toupdate.adminPhone = request.json['adminPhone']
        if validations:
            abort(400, "cannot update admin account", errors=validations)
        db.session.add(toupdate)
        safeCommit()
        return {
                   "result": {"message": "Successfully updated organization account administrator record."}
                 }, 201

    else:
        abort(400, "No Organisation Account Admin Record found.")


def getSingleAccountAdminRecords(request, accountId, adminId):
    qryRes = AccountAdministrator.query.filter_by(accountId=accountId).filter_by(adminId=adminId).all()
    if qryRes:
        return {
                   "result": qryRes[0],
                 }, 200
    else:
        abort(400, "No Organisation Account Admin Record found.")


def deleteSingleAccountAdminRecords(request, accountId, adminId):
    qryRes = AccountAdministrator.query.filter_by(adminId=adminId).all()
    # otpRes = OneTimePassword.query \
    #     .filter_by(adminId=adminId).delete()
    #
    # adminRegisterResult = AccountAdministratorRegistration.query \
    #                         .filter_by(adminId=adminId).delete()

    if qryRes:
        if delete_record(AccountAdministrator, AccountAdministrator.adminId, adminId):
            return {
                   "result": {"message": "Successfully deleted organization account administrator."}
                }, 200
        else:
            abort(400, "Unable to delete organisation admin record.")
    else:
        abort(400, "No Organisation Account Admin Record found.")


def resetSingleAccountAdminRecords(request, accountId, adminId):
    return {"result": { "message": "Not Implemented"}}, 404


########### Account Billing #######


def createAccountBillingRecords(request, accountId):
    payload = request.json
    r = AccountBilling(accountId, payload)
    print(r)
    db.session.add(r)
    try:
        safeCommit()
        return {
                   "result": {"message": "Successfully added organisation account billing record."}
                 }, 201
    except Exception as e:
        print(str(e))
        abort(400, "Unable to create.")


def getAllAccountBillingRecords(request, accountId):
    qryRes = AccountBilling\
                  .query\
                  .filter_by(accountId=accountId)\
                  .all()

    return {
               "result": qryRes,
            }, 200


########### Single Account Billing #######


def updateSingleAccountBillingRecords(request, accountId, billingId):
    qryRes = AccountBilling\
                  .query\
                  .filter_by(accountId=accountId)\
                  .filter_by(billingId=billingId)\
                  .all()

    if qryRes:
        toupdate = qryRes[0]
        if request.json['suspensionDate'] < request.json['paymentDueDate']:
            abort(400, "Suspension date should be greater than due date")
        if 'paymentDueDate' in request.json:
            toupdate.paymentDueDate = request.json['paymentDueDate']
        if 'notifyFrequency' in request.json:
            toupdate.notifyFrequency = request.json['notifyFrequency']
        if 'suspensionDate' in request.json:
            toupdate.suspensionDate = request.json['suspensionDate']
        if 'deactivationDate' in request.json:
            toupdate.deactivationDate = request.json['deactivationDate']

        safeCommit()
        return {
                   "result": {"message": "Successfully updated organisation account billing record."}
                 }, 200
    else:
        abort(400, "No Organisation account billing record found.")


def createAccountUsageRecords(request, accountId):
    payload = request.json
    r = AccountUsage(accountId, payload)
    db.session.add(r)
    try:
        safeCommit()
        return {
                   "result": {"message": "Successfully added organisation account usage record."}
                 }, 201
    except Exception as e:
        print(str(e))
        abort(400, "Unable to create.")


def getAccountUsageRecords(accountId,month):
    try:
        param = month
    except:
        param = datetime.now(datetime.strftime('%m-%Y'))

    fd,ld = get_month_day_range(param)
    print(fd)
    print(ld)
    try:
        qryRes = AccountUsage\
              .query\
              .filter_by(accountId = accountId)\
              .filter(AccountUsage.usageDate >= fd, AccountUsage.usageDate <= ld) \
              .all()

        return {
            "result": qryRes,
               }, 200
    except:
        abort(400, "Unable to get account usage records.")


def check_email(request):
    email = request.args.get('emailId').lower()
    query_admin = PortalAdministrator.query. \
                    filter(PortalAdministrator.portalLogin == email).one_or_none()

    if query_admin:
        return {
            "result": {
                "rounds": query_admin.rounds,
                "salt": query_admin.salt
                }
            }, 200
    abort(400, "There is no user registered with this email address.")

def logInUser(request):
    payload = request.json
    username = payload.get('email').lower()
    password = payload.get('password')
    registered = employee.query.filter_by(email=username).one_or_none()
    if registered and password == registered.password:
        return {
                   "result": {"message": "Successfully logged in."}
                }, 200
    else:
        return abort(400, "User not found.")
                
    



def logInUser(request):
    payload = request.json
    username = payload.get('email').lower()
    password = payload.get('password')
    token = payload.get('token')
    admin = guardSaaSAdmin.authenticate(username, password)
    if admin:
        # TOTP Verification
        print(ENABLE_MFA_LOGIN)
        if ENABLE_MFA_LOGIN=="true":
            if admin.totpKey is None:
                registered = PortalAdministratorRegistration.query.filter_by(portalAdminId=admin.portalAdminId).one_or_none()
                if not registered:
                    totp = TotpFactory.new(digits=6)
                    registration_obj = PortalAdministratorRegistration(portalAdminId=admin.portalAdminId, secretToken=totp.to_json())
                    db.session.add(registration_obj)
                    safeCommit()
                    return {
                        "result": {
                            "access_token": None,
                            "name": admin.firstName + " " + admin.lastName,
                            "email": admin.email,
                            "key_gen_pending": None,
                            "registrationId": registration_obj.registrationId
                        }
                       }, 200
                else:
                    return {
                               "result": {
                                   "access_token": None,
                                   "name": admin.firstName + " " + admin.lastName,
                                   "email": admin.email,
                                   "key_gen_pending": None,
                                   "registrationId": registered.registrationId
                               }
                           }, 200


            try:
                match = TotpFactory.verify(token, admin.totpKey)
            except (MalformedTokenError, TokenError)as err:
                print("Token verification failed {error}".format(**{"error": str(err)}))
                abort(401, "Cannot login, token mismatch error.")
        jwt_token = guardSaaSAdmin.encode_jwt_token(admin)
        # result = SaaSAdminJWT(str(jwt_token))
        # db.session.add(result)
        # safeCommit()
        admin.lastAccess = datetime.now()
        db.session.add(admin)
        safeCommit()
        return {
                   "result": {
                       "access_token": jwt_token,
                       "name": admin.firstName+admin.lastName,
                       "email": admin.email,
                       "key_gen_pending": admin.extras.get('keyGenPending')
                   }
               }, 200
    else:
        abort(400, "Invalid email or password.")


def logOutUser(request,old_token):
    qryRes = SaaSAdminJWT \
        .query \
        .filter_by(jwt=old_token) \
        .all()

    if qryRes:
        o = qryRes[0]
        db.session.delete(o)
        safeCommit()
        return {
                   "result": {"message": "Successfully deleted token record."}
                }, 200

    else:
        abort(400, "No token record found.")


def refreshToken(old_token):
    try:
        new_token = guardSaaSAdmin.refresh_jwt_token(old_token)
    except (saftrus_rbac.exceptions.InvalidTokenHeader, saftrus_rbac.exceptions.EarlyRefreshError) as e:
        print(str(e))
        abort(400, "Error : Invalid token header or Token may need not refresh.")
    except Exception as e:
        print(str(e))
        abort(400, "Cannot refresh token")
    else:
        result = {
                     "result": {"refresh_token": new_token}
         }, 200
    return result


def SaaSPasswordUpdate(request, portalAdminId):
    payload = request.json
    qryRes = PortalAdministrator\
            .query\
            .filter(and_(PortalAdministrator.portalAdminId == portalAdminId, PortalAdministrator.password == payload.get('password')))\
            .all()
    print(qryRes)
    if qryRes:
        toupdate = qryRes[0]
        if 'new_password' in request.json:
            toupdate.password = request.json['new_password']
        safeCommit()
        return {
                   "result": {"message": "Successfully updated SaaS account password."}
                }, 200

    else:
        abort(400, "Cannot update password, credentials does not match.")


def createBillingTierRecord(request, profileid):
    list = BillingTiers.query.filter_by(profileId=profileid).all()
    count = len(list)
    payload = request.json
    result = BillingTiers(payload, profileid)
    if count:
        highest_upperlimit = BillingTiers.query.filter_by(profileId=profileid).order_by(desc(BillingTiers.userUpperLimit)).first()
        result.userLowerLimit = highest_upperlimit.userUpperLimit + 1
        result.tierName = "Tier " + str(count+1)
    else:
        result.tierName = "Tier 1"
        result.userLowerLimit = 1
    if result.userUpperLimit <= result.userLowerLimit:
        abort(400, "Cannot create billing tier.", errors={"userUpperLimit":"Upper limit should be greater than "+str(result.userLowerLimit)})
    try:
        db.session.add(result)
        safeCommit()
        return {
            "result": {"message": "Successfully added billing tier record."}
            }, 200
    except Exception as e:
        print(str(e))
        abort(400, "Unable to create billing tier.")


def getAllBillingTierRecords(profileid):
    result = BillingTiers.query.filter_by(profileId=profileid).all()

    return {
               "result": result
            }, 200


def getBillingTierRecord(profileid, tierid):
    result = BillingTiers.query.filter_by(tierId = tierid, profileId = profileid).all()

    if result:
        return {
                   "result": result[0]
                }, 200
    return {
        "result": []
    }, 200


def deleteBillingTierRecord(profileid, tierid):
    result = BillingTiers.query.filter_by(profileId=profileid, tierId = tierid).all()
    if result:
        tiers = BillingTiers.query.filter_by(profileId=profileid).order_by(BillingTiers.tierId).all()
        lastTier = tiers[-1]
        print(lastTier)
        if tierid != lastTier.tierId:
            nextRow = BillingTiers.query.filter_by(profileId=profileid).order_by(BillingTiers.id).filter(BillingTiers.id>result[0].id).first()
            nextRow.userLowerLimit = result[0].userLowerLimit
            tiername = result[0].tierName
            while nextRow:
                try:
                    temp_tiername = nextRow.tierName
                    nextRow.tierName = tiername
                    db.session.add(nextRow)
                    db.session.flush()
                    nextRow = BillingTiers.query.filter_by(profileId=profileid).order_by(BillingTiers.id).filter(BillingTiers.id>nextRow.id).first()
                    tiername = temp_tiername
                except:
                    abort(400, "Unable to delete the billing tier.")


        try:
            if delete_record(BillingTiers, BillingTiers.tierId, tierid):
                return {
                       "result": {"message": "Billing tier deleted successfully."}
                    }, 200
            else:
                abort(400, "Unable to delete billing tier record.")
        except Exception as e:
            print("in excpetion handler")
            print(str(e))
            abort(400, "Unable to delete billing tier.")
    else:
        abort(400, "BillingTier record do not exists with this Id.")


def updateBillingTierRecord(request, profileid, tierid):
    qryRes = BillingTiers.query.filter_by(tierId = tierid, profileId = profileid).all()
    if qryRes:
        toupdate = qryRes[0]
        if 'userUpperLimit' in request.json:

            toupdate.userUpperLimit = request.json['userUpperLimit']
        if 'userCost' in request.json:
            toupdate.userCost = request.json['userCost']

        safeCommit()
        return {
                   "result": {"message": "Successfully updated billing tier record."}
                }, 200
    else:
        abort(400, "No billingtier record found.")


def getAllPortalAdmins():
    result = PortalAdministrator.query.filter(PortalAdministrator.deletedOn==None).all()

    return {
               "result": result
            }, 200


def createPortalAdmin(request):
    payload = request.json
    validations = dict()
    if not validate_name(payload.get('firstName')):
        validations['firstName'] = "first name should be a proper name"
    if not validate_name(payload.get('lastName')):
        validations['lastName'] = "last name should be a proper name"
    if not validate_email(payload.get('email')):
        validations['email'] = "email should be a proper email id"
    if not validate_phonenumber(payload.get('phoneNumber')):
        validations['phoneNumber'] = "phone number should be a proper phone number"
    if validations:
        abort(400, "cannot create a saas admin", errors=validations)

    result = PortalAdministrator(payload)
    error_list = dict()
    try:
        if not validate_unique_key(PortalAdministrator, PortalAdministrator.email, result.email):
            error_list['email'] = "email id already exists"
        if error_list:
            abort(400, "Cannot create account.", errors=error_list)
        else:
            if result:
                db.session.add(result)
                safeCommit()

                otp_obj = PortalAdminOTP()
                otp_obj.portalAdminId = result.portalAdminId
                otp_obj.portalAdminOTP = generate_random(32)
                otp_obj.portalAdminOTPCreation = datetime.now()
                otp_obj.portalAdminOTPExpiryDate = datetime.now() + timedelta(days=1)
                db.session.add(otp_obj)
                safeCommit()

                context = MailContext(name= result.firstName+" "+result.lastName,email=result.email, otp=otp_obj.portalAdminOTP)
                send_email(template_file="email/saasadmin-account-registration.html",
                           subject="Verify your Cydrive SaaS account",
                           recipients=[result.email],
                           context=context)
                return {
                   "result": {"message": "Successfully added a SaaS administrator record."}
                }, 200
            else:
                abort(400, "Unable to create a SaaS administrator account.")
    except Exception as e:
        print(str(e))
        abort(400, "Cannot create SaaS administrator account.", errors=error_list)


def getPortalAdmin(portalAdminId):
    result = PortalAdministrator.query \
            .filter_by(portalAdminId=portalAdminId).all()

    if result:
        return {
                   "result": result[0]
                }, 200
    else:
        abort(400, "Unable to get the record using the provided portalAdminId.")


def updatePortalAdmin(request, portalAdminId):
    result = PortalAdministrator.query \
            .filter_by(portalAdminId=portalAdminId).all()

    if result:
        toupdate = result[0]
        validations = dict()
        if 'firstName' in request.json:
            if not validate_name(request.json['firstName']):
                validations['firstName'] = "first name should be a proper name"
            toupdate.firstName = request.json['firstName']
        if 'lastName' in request.json:
            if not validate_name(request.json['lastName']):
                validations['lastName'] = "last name should be a proper name"
            toupdate.lastName = request.json['lastName']
        if 'phoneNumber' in request.json:
            if not validate_phonenumber(request.json['phoneNumber']):
                validations['phoneNumber'] = "phone number should be a proper phone number"
            toupdate.phoneNumber = request.json['phoneNumber']
        if validations:
            abort(400, "Cannot update saas admin account.", errors=validations)
        db.session.add(toupdate)
        safeCommit()
        return {
                   "result": {"message": "Successfully updated SaaS administrator account record."}
                 }, 200

    else:
        abort(400, "No Portal Administrator account Record found.")


def deletePortalAdmin(portalAdminId):
    result = PortalAdministrator.query.filter_by(portalAdminId=portalAdminId).one_or_none()
    if result.email == 'default.user@email.com':
        abort(400, "Cannot delete the default portal administrator.")
    if result:
        if delete_record(PortalAdministrator, PortalAdministrator.portalAdminId, portalAdminId):
            return {
                   "result": {"message": "Successfully deleted SaaS administrator account."}
                }, 200
        else:
            abort(400, "Unable to delete SaaS administrator record.")
    else:
        abort(400, "unable to get the portal administrator account using the portalAdminId.")


def getOTP(accountId, adminid):
    query = OneTimePassword.query.filter_by(adminId=adminid).order_by(desc(OneTimePassword.adminOTPExpiryDate)).first()
    if not query:
        return {"result": []}, 200
    expiry_date = query.adminOTPExpiryDate
    valid = True if datetime.today() < expiry_date else False
    result = {
        'adminOTP': query.adminOTP,
        'adminOTPExpiryDate': query.adminOTPExpiryDate,
        'Valid': valid
    }
    return {"result": result}, 200


def regenerateOTP(accountId, adminid, request):
    query = OneTimePassword.query.filter_by(adminId=adminid).one_or_none()
    if query:
        if request.json.get('adminOTP'):
            query.adminOTP = request.json.get('adminOTP')
        else:
            query.adminOTP = generate_random()
        query.adminOTPCreation = datetime.now()
        query.adminOTPExpiryDate = datetime.now() + timedelta(days=7)
        try:
            db.session.add(query)
            safeCommit()
            admin = AccountAdministrator.query.filter_by(adminId=adminid).one()
            account = Account.query.filter_by(accountId=admin.accountId).one()
            admin_registration_record = AccountAdministratorRegistration.query.filter_by(adminId=adminid).one_or_none()
            if admin_registration_record and admin_registration_record.expired is not None:
                context = MailContext(name=admin.adminName,
                                      account_name=account.accountName,
                                      account_url="https://" + account.accountSubDomain,
                                      email=admin.adminEmail,
                                      activate="https://" + account.accountSubDomain + "/#/reset-pwd",
                                      otp=query.adminOTP)
                # Send out an email
                try:
                    send_email(template_file="email/enterprise-admin-password-reset.html",
                               subject="Password reset for your Cydrive administrator account",
                               recipients=[admin.adminEmail],
                               context=context)
                except Exception as ex:
                    print("Unable to send email -", str(ex))
                    raise ex
                return {
                           "result": {"message": "Successfully updated OTP."}
                    }, 201
            context = MailContext(name=admin.adminName,
                                  account_name=account.accountName,
                                  account_url="https://" + account.accountSubDomain,
                                  email=admin.adminEmail,
                                  activate="https://" + account.accountSubDomain + "/#/enterprise-activation",
                                  otp=query.adminOTP)
            try:
                send_email(template_file="email/enterprise-admin-otp-reset.html",
                           subject="Activate your Cydrive administrator account",
                           recipients=[admin.adminEmail],
                           context=context)
            except Exception as ex:
                print("Unable to send email -", str(ex))
                raise ex
            return {
                       "result": {"message": "Successfully updated OTP."}
                   }, 201
        except Exception as e:
            print(str(e))
            abort(400, "Unable to add OTP record."+str(e))
    abort(400, "OTP is not found for this saas admin.")


def generateOTP(request):
    portalAdminId = request.args.get('portalAdminId')
    # Generate OTP
    totp = TotpFactory.new(digits=6)
    d = datetime.now()

    # Insert OR Update
    querystr = PortalAdminOTP \
        .query \
        .filter_by(portalAdminId=portalAdminId) \
        .all()
    token_obj = totp.generate()
    if querystr:
        updateqstr = querystr[0]
        updateqstr.portalAdminOTP = totp.to_json()
        updateqstr.portalAdminOTPCreation = d
        updateqstr.portalAdminOTPExpiryDate = token_obj.expire_time
    else:
        # Create New Record
        totSaftrusObj = PortalAdminOTP(portalAdminId=portalAdminId, portalAdminOTP=totp.to_json(), portalAdminOTPCreation=d,
                                    portalAdminOTPExpiryDate=token_obj.expire_time)
        print(totSaftrusObj)
        db.session.add(totSaftrusObj)

    try:
        safeCommit()

        return {"result": {"otp": token_obj.token}}, 200
    except:
        abort(400, "Could not generate OTP.")

def getAdminIdByEmail(email):
    queryres = PortalAdministrator \
        .query \
        .filter(and_(PortalAdministrator.email == email, PortalAdministrator.deletedOn == None)) \
        .all()
    print(queryres)
    if queryres:
        return queryres[0].portalAdminId
    else:
        return None


# get adminId -> qry OTP table to find out the TOTP  -->try to verify it -->
# if successfully verified, mark the OTP as invalid, and create a registration record
# create a new TOTP object to handle registration verification and save it to registration table
def handleRegistration(request):
    email = request.get('email').strip().lower()
    otp = request.get('otp').strip()
    print(email)
    print(otp)
    # adminId = getAdminIdByEmail(email)
    #
    # querystr = OneTimePassword \
    #     .query \
    #     .filter_by(adminId=adminId) \
    #     .all()

    result = PortalAdminOTP\
        .query.join(PortalAdministrator,
                    PortalAdminOTP.portalAdminId == PortalAdministrator.portalAdminId)\
        .filter(PortalAdminOTP.portalAdminOTP == otp,
                PortalAdministrator.email == email)\
        .add_columns(PortalAdministrator.portalAdminId).one_or_none()

    if result:
        valid = True if (datetime.now() < result.PortalAdminOTP.portalAdminOTPExpiryDate) else False
        if valid:

            totp = TotpFactory.new(digits=6)
            if request.get('reset')==True:
                registration_obj = PortalAdministratorRegistration.query.filter_by(portalAdminId=result.portalAdminId).one_or_none()
                registration_obj.secretToken = totp.to_json()
                registration_obj.expired = False
            else:
                existing_registration = PortalAdministratorRegistration.query.filter_by(portalAdminId=result.portalAdminId).one_or_none()
                if existing_registration:
                    registration_obj = existing_registration
                    registration_obj.secretToken = totp.to_json()
                else:
                    registration_obj = PortalAdministratorRegistration(portalAdminId=result.portalAdminId, secretToken=totp.to_json())
            db.session.add(registration_obj)
            db.session.flush()
            result.PortalAdminOTP.portalAdminOTPExpiryDate = datetime.now();
            db.session.add(result.PortalAdminOTP)
            db.session.flush()
            db.session.commit()
            return {"result": {"registrationId": registration_obj.registrationId}}, 200
        abort(400, "your OTP has expired, please contact your administrator to reset your OTP.")
    abort(400, "Incorrect login information provided. Please try again.")


# lookup registration --> get totp object -->
# check if the registration is not expired
#    --> verify 2 otp
#    --> successful registration
#    --> registration id will then become invalid

def verifyRegistration(request):
    registrationId = request.get('registrationId')
    otp1 = request.get('token1')
    otp2 = request.get('token2')
    if otp1 == otp2:
        abort(400, "Authentication Code 1 and Authentication Code 2 should be different tokens.Please try again")
    password = request.get('password')
    print("password is-->"+password)
    rounds = request.get('rounds')
    salt = request.get('salt')
    print(registrationId)
    print(otp1)
    print(otp2)
    #confirm_pass = request.args.get('cpassword')

    # if confirm_pass != password:
    #     pass    # TODO: handle things gracefully

    registrationObj = PortalAdministratorRegistration \
        .query \
        .filter_by(registrationId=registrationId) \
        .one_or_none()

    if registrationObj:
        secretToken = registrationObj.secretToken
        totp = TotpFactory.from_json(secretToken)
        try:
            print("Token 1: " + otp1)
            print("Token 2: " + otp2)
            print("Generated: " + totp.generate().token)
            if not registrationObj.expired \
                    and totp.verify(otp2, secretToken) \
                    and totp.verify(otp1, secretToken, window=60):
                registrationObj.expired = True
                registrationObj.expiryDate = datetime.now()
                db.session.add(registrationObj)
                db.session.flush()

                # save the admin account
                adminObj = PortalAdministrator.query.filter_by(portalAdminId=registrationObj.portalAdminId).one()
                print(adminObj)
                adminObj.totpKey = secretToken
                adminObj.password = password
                adminObj.rounds = rounds
                adminObj.salt = salt
                db.session.add(adminObj)
                db.session.commit()
                print(adminObj.password)
                return {"result": {"message": "Valid Registration."}}, 200
            abort(400, "Invalid OTP/Registration.")
        except Exception as exp:
            print(exp)
            abort(400, "Invalid OTP/Registration, "+str(exp))
    else:
        abort(400, "No such registration id found.")


def generateQRImage(request):
    registration_id = request.get('registrationId')
    registration_obj = PortalAdministratorRegistration \
        .query.filter(
            PortalAdministratorRegistration.registrationId == registration_id,)\
        .one()
    admin = PortalAdministrator.query.filter_by(portalAdminId=registration_obj.portalAdminId).one()
    totp = TotpFactory.from_json(registration_obj.secretToken)
    uri = totp.to_uri(label=admin.email)
    qrurl = pyqrcode.create(uri)
    outputBuffer = BytesIO()
    qrurl.png(outputBuffer, scale=5)
    outputBuffer.seek(0)
    return {"image": base64.b64encode(outputBuffer.getvalue()).decode()}


def getCurrentSaasAdminInfo():
    try:
        saas_admin = saftrus_rbac.current_user()
        return {
                   "result": {
                       "portalAdminId": saas_admin.portalAdminId,
                       "firstName": saas_admin.firstName,
                       "lastName": saas_admin.lastName,
                       "email": saas_admin.email,
                       "phoneNumber": saas_admin.phoneNumber,
                       "lastAccess": saas_admin.lastAccess,
                       "createdOn": saas_admin.createdOn
                   }
               }, 200
    except Exception as e:
        print(str(e))
        abort(400, "Unable to get current saas admin info.")


def createBillingProfileRecord(request):
    payload = request.json
    validations = dict()
    if not validate_name(payload.get('billingProfileName')):
        validations['billingProfileName'] = "billing profile name should be a proper name"
    if validations:
        abort(400, "cannot create billing profile record", errors=validations)
    record = AccountBillingProfile(payload)
    if record:
        if not validate_unique_key(AccountBillingProfile, AccountBillingProfile.billingProfileName, record.billingProfileName):
            validations['billingProfileName'] = "billing profile name already exists"
        if validations:
            abort(400, "Cannot create billing profile record.", errors=validations)
        try:
            db.session.add(record)
            safeCommit()
            return {
                "result": {"message": "Created a billing profile record successfully."}
                }, 201
        except Exception as e:
            print(str(e))
            abort(400, "Cannot save billing record.Please try again.")
    abort(400, "Cannot create billing profile record.")


def getAllBillingProfiles():
    query = AccountBillingProfile.query.all()

    return {
        "result": query
    }, 200


def getBillingProfileRecord(profileid):
    query = AccountBillingProfile.query.filter_by(profileId=profileid).one_or_none()
    if query:
        return {
                   "result": query
               }, 200
    return {
               "result": []
           }, 200


def updateBillingProfile(request, profileid):
    query = AccountBillingProfile.query.filter_by(profileId=profileid).all()
    if query:
        validations = dict()
        update = query[0]
        if 'billingProfileName' in request.json:
            if not validate_name(request.json['billingProfileName']):
                validations['billingProfileName'] = "billing profile Name should be a proper name"
            update.billingProfileName = request.json['billingProfileName']
        if 'frequency' in request.json:
            update.frequency = request.json['frequency']
        if validations:
            abort(400, "cannot update billing profile record", errors=validations)
        if not validate_unique_key_put(AccountBillingProfile, AccountBillingProfile.billingProfileName, AccountBillingProfile.profileId, profileid, update.billingProfileName):
            validations['billingProfileName'] = "billing profile name already exists"
        if validations:
            abort(400, "billing profile name already exists,please choose another name")
        safeCommit()
        return {
                   "result": {"message": "Successfully updated billing profile record."}
               }, 200

    else:
        abort(400, "No billing profile record found.")


def deleteBillingProfile(profileid):
    if profileid == '1aP000001' or profileid == '1aP000002':
        abort(400, "Cannot delete default billing profile record.")
    record = AccountBillingProfile.query.filter_by(profileId=profileid).all()
    if record:
        query = Account.query.filter_by(profileId=profileid).all()
        if not query:
            if delete_record(AccountBillingProfile, AccountBillingProfile.profileId, profileid):
                return {
                    "result": {
                        "message": "Successfully deleted billing profile record."
                        }
                       }, 201
        abort(400, "Cannot delete this billing profile record as it is linked to some existing customer accounts.")
    else:
        abort(400, "Billing profile record not found.")


def sendInvoice(request):
    payload = request.json
    accountid = payload.get('accountId')
    account = Account.query.filter(Account.accountId == accountid).one_or_none()
    if not account:
        abort(400, "Account not found, cannot send invoice.")
    try:
        sqltxt = AccountBilling.query.filter(AccountBilling.accountId==accountid, or_(AccountBilling.receiptPDF != None, AccountBilling.invoicePDF != None)).order_by(desc(AccountBilling.billingDate)).first()
        if sqltxt is not None:
                context = MailContext(
                    name=account.pocName,
                    month=sqltxt.billingDate.strftime("%B"),
                )

                send_email(template_file="email/invoice.html",
                           subject="Cydrive{0}{1} Enterprise Invoice/Receipt".format('\u1D40', '\u1D39'),
                           recipients=[account.billingEmailAddress], context=context, attachment=sqltxt.receiptPDF if sqltxt.invoiceSent else sqltxt.invoicePDF,
                           filename=('Receipt_' if sqltxt.invoiceSent else 'Invoice_') + account.accountName + '_' + sqltxt.billingDate.strftime("%B") + '.pdf')

                return {
                    "result": {"message": "Sent invoice to mail id: "+account.billingEmailAddress}
                },200
        return {
                   "result": {"message": "No billing records found, cannot send invoice"}
               }, 200
    except Exception as e:
        print(e)
        abort(400, "Could not send invoice, please try again later.")



def forgotPassword(request):
    emailId = request.args.get('emailId').lower()
    query_admin = PortalAdministrator.query.filter_by(email=emailId).one_or_none()
    if not query_admin:
        abort(400,"SAAS administrator with this email address does not exists")
    if query_admin.password is None:
        abort(400,"You have not activated your account, Please activate your account.")
    otp = generate_random(32)
    existing_otp = PortalAdminOTP.query.filter_by(portalAdminId=query_admin.portalAdminId).order_by(desc(PortalAdminOTP.portalAdminOTPExpiryDate)).first()
    existing_otp.portalAdminOTP = otp
    existing_otp.portalAdminOTPCreation = datetime.now()
    existing_otp.portalAdminOTPExpiryDate = datetime.now() + timedelta(days=7)
    try:
        db.session.add(existing_otp)
        safeCommit()
    except Exception as e:
        print(str(e))
        abort(500,"Unable to generate otp record, database error occurred")

    context = MailContext(
        name=query_admin.firstName+" "+query_admin.lastName,
        email=query_admin.email, otp=existing_otp.portalAdminOTP,url="https://portal.cydrive.com/#/reset-password"
        )
    try:
        send_email(template_file="email/saas-admin-password-reset.html",
                   subject="Password reset request for your Cydrive SaaS administrator account",
                   recipients=[query_admin.email],
                   context=context)
    except Exception as ex:
        print("Unable to send email -", str(ex))
        abort(400,"Could not send email with OTP")

    return {
        "result": {"message" : "OTP has been sent successfully to your email ID."}
    }, 201

def InitialData(payload):
    try:
        email = payload.get('email').lower()
        password = payload.get('password')
        portalAdmin = PortalAdministrator.query.filter_by(email=email).one_or_none()
        if portalAdmin:
            print(portalAdmin.password)
            if portalAdmin.password == password:
                if portalAdmin.totpKey:
                    return {
                        "message": "TOTP already exists for this SaaS admin",
                        "totp": portalAdmin.totpKey
                    }, 200
                totp = TotpFactory.new(digits=6)
                update_portalAdmin = PortalAdministrator.query.filter_by(portalAdminId='1xP000001').one_or_none()
                update_portalAdmin.totpKey = totp.to_json()
                db.session.add(update_portalAdmin)
                safeCommit()
                return {
                    "message": "Successfully inserted new secret token",
                    "totp": str(totp.to_json())
                }, 200
            return {
                       "message": "Invalid credentials",
                       "totp": None
                   }, 400
        return {
                   "message": "SaaS admin not found",
                   "totp": None
               }, 400
    except Exception as e:
        print(str(e))
        return {
                   "message": "unable to save secret token",
                    "totp": None
               }, 400


def createUpgrade(request):
    try:
        upgrade = Upgrade(request)
        db.session.add(upgrade)
        safeCommit()
        return {
            "result": {"message": "Successfully created upgrade record"}
        }, 201
    except Exception as e:
        print(str(e))
        abort(400, "Cannot create new upgrade record")
        # return {
        #     "result": {"message": "Cannot create new upgrade record"}
        # }, 400

def listUpgrades():
    try:
        upgrades = Upgrade.query.all()
        print(upgrades)
        list = []
        for upgrade in upgrades:
            model = {
                'upgradeId': upgrade.upgradeId,
                'package': upgrade.package,
                'releaseNotes': upgrade.releaseNotes,
                'supportedVersions': upgrade.supportedVersions,
                'packageInformation': upgrade.version if upgrade.description is '' else upgrade.version + ", " + upgrade.description,
                'upgradeStatus': upgrade.upgradeStatus,
                'checkSum': upgrade.checkSum
            }
            list.append(model)
        return {
            "result": list
        }, 200
    except Exception as e:
        print(str(e))
        abort(400, "Error in displaying upgrade records")
        # return {
        #     "result": {"message": "Error in displaying upgrade records"}
        # }, 400

def updateUpgrade(upgradeId):
    try:
        record = Upgrade.query.filter_by(upgradeId=upgradeId).one_or_none()
        print(record)
        if not record:
            return {
                "result": {"message": "No upgrade found with this upgrade ID"}
            }, 200
        if record.upgradeStatus == 'AVAILABLE':
            record.upgradeStatus = 'DISTRIBUTED'
            record.releaseDate = datetime.now()
            db.session.add(record)
            safeCommit()
            accounts = Account.query.filter_by(supportTier='PLATINUM TIER').all()
            for account in accounts:
                admins = AccountAdministrator.query.filter_by(accountId=account.accountId).all()
                for admin in admins:
                    context = MailContext(name=admin.adminName,
                                          account_name=account.accountName,
                                          email=admin.adminEmail
                                          )
                    # Send out an email
                    try:
                        send_email(template_file="email/upgrade-notify.html",
                                   subject="Cydrive Upgrade Notification",
                                   recipients=[admin.adminEmail],
                                   context=context)
                    except Exception as ex:
                        print("Unable to send email -", str(ex), "to ", admin.adminEmail)
            for account in accounts:
                print(account.accountId)
                enterpriseUpgrade = EnterpriseUpgrade()
                enterpriseUpgrade.upgradeId = record.upgradeId
                enterpriseUpgrade.package = record.package
                enterpriseUpgrade.releaseNotes = record.releaseNotes
                enterpriseUpgrade.requiredVersions = record.supportedVersions
                enterpriseUpgrade.description = record.description
                enterpriseUpgrade.version = record.version
                enterpriseUpgrade.releaseDate = record.releaseDate
                enterpriseUpgrade.accountId = account.accountId
                enterpriseUpgrade.checkSum = record.checkSum
                eaupgradeRecords = EnterpriseUpgrade.query.filter_by(accountId=account.accountId, upgradeStatus='DISTRIBUTED').all()
                print(eaupgradeRecords)
                eaupgradefullRecords = EnterpriseUpgrade.query.filter_by(accountId=account.accountId).all()
                print(eaupgradefullRecords)
                if eaupgradeRecords:
                    for eaupgrade in eaupgradeRecords:
                        # print(eaupgrade)
                        # print(eaupgrade.version)
                        # print(eaupgrade.upgradeStatus)
                        if eaupgrade.version in record.supportedVersions and eaupgrade.upgradeStatus == 'DISTRIBUTED':
                            print("done")
                            enterpriseUpgrade.upgradeStatus = 'AVAILABLE'
                elif not eaupgradefullRecords:
                    enterpriseUpgrade.upgradeStatus = 'AVAILABLE'
                else:
                    enterpriseUpgrade.upgradeStatus = 'UNSUPPORTED'
                db.session.add(enterpriseUpgrade)
                safeCommit()
            return {
                "result": {"message": "Successfully changed upgrade record " + record.upgradeId + " to " + record.upgradeStatus}
                }, 201
        return {
            "result": {"message": "Cannot change to AVAILABLE"}
        }, 200
    except Exception as e:
        print(str(e))
        abort(400, "Cannot change the state")
        # return {
        #     "result": {"message": "Cannot change the state"}
        # }, 400


def getVersions():
    try:
        versions = Upgrade.query.all()
        # print(versions)
        a = list()
        for version in versions:
            # print(version)
            a.append(version)
        return {
            "result": a
        }, 200
    except Exception as e:
        print(str(e))
        abort(400, "cannot display versions list")
        # return {
        #     "result": {"message": "cannot display versions list"}
        # }, 400


def modifyBillingProfile(request, profileid):
    billingProfileRecord = AccountBillingProfile.query.filter_by(profileId=profileid).one_or_none()
    if not billingProfileRecord:
        abort(400, "billing profile record not found")
    billingProfileRecord.profileId = request.get('profileId')
    db.session.add(billingProfileRecord)
    safeCommit()
    return {
        "result":{"message":"Successfully updated billing profile record"}
    }, 201


def modifyBillingTier(request, tierid):
    billingTierRecord = BillingTiers.query.filter_by(tierId=tierid).one_or_none()
    if not billingTierRecord:
        abort(400, "billing profile record not found")
    billingTierRecord.tierId = request.get('tierId')
    db.session.add(billingTierRecord)
    safeCommit()
    return {
        "result":{"message":"Successfully updated billing tier record"}
    }, 201


def getUpgradePackages():
    # S3FilesList = s3_client.list_objects(Bucket='landing.cydrive.com')
    # Prefix = 'landing.cydrive.com/downloads/Upgrades/
    # bucket = s3_resource.Bucket('landing.cydrive.com')
    # print(bucket)
    # for file in bucket.objects.filter(Prefix='downloads/Upgrades/'):
    #     print(file.key)
    #     print(type(file))
    bucket = s3_client.list_objects_v2(Bucket='landing.cydrive.com', Prefix='downloads/Upgrades/')
    print(bucket)

    s3files = []
    for file in bucket['Contents']:
        if file['Key'] == 'downloads/Upgrades/':
            continue
        record = dict()
        fileName = file['Key'].split('/')
        fileName = fileName[2]
        print("path--", 'https://www.cydrive.com/' + file['Key'])
        path = 'https://www.cydrive.com/' + file['Key']
        record['fileName'] = fileName
        record['path'] = path
        s3files.append(record)

    showFiles = list()
    upgradeRecords = Upgrade.query.all()
    for file in s3files:
        if file['path'] not in [record.package for record in upgradeRecords]:
            showFiles.append(file)


    return {
        "result": showFiles
    }, 200


def modifySuspensionStatus(accountId):
    account = Account.query.filter_by(accountId = accountId).one_or_none()
    if not account:
        abort(400,"Account not found")
    if not account.isSuspended:
        message = "Account suspended successfully"
        account.isSuspended = True
    else:
        message = "Account suspension removed successfully"
        account.isSuspended = False
    db.session.add(account)
    safeCommit()
    return {
               "result": {"message": message }
           }, 201


def modifyPaymentStatus(accountId,billingId,portalAdminId):
    billingRecord = AccountBilling.query.filter_by(accountId = accountId,billingId = billingId).one_or_none()
    portalAdmin = PortalAdministrator.query.filter_by(portalAdminId = portalAdminId).one_or_none()
    account = Account.query.filter_by(accountId=accountId).one_or_none()
    invoice_date = billingRecord.billingDate.replace(day=1) + relativedelta(months=1)
    if not billingRecord:
        abort(400,"Billing record not found")
    if not billingRecord.paymentMade:
        amount_paid = billingRecord.billingAmount
        device_count = 0
        months = 1
        get_records = Invoice.query.filter_by(accountId=accountId, billingDate=billingRecord.billingDate).all()
        for get_record in get_records:
            device_count = device_count + get_record.billedDevices
            months = get_record.numberOfMonths
        support_tier = SupportTier.query.filter_by(name=billingRecord.supportTier).one_or_none()
        support_total_cost = (device_count * support_tier.cost * months)
        amount_paid = amount_paid + support_total_cost
        print(amount_paid)
        receipt_number = account.accountName+'_'+invoice_date.strftime("%d-%B-%Y")
        invoice_number = account.accountName+'_'+invoice_date.strftime("%d-%B-%Y")
        billepoch = datetime.now().timestamp()
        payment_method = 'Invoice-Me'
        from api.common.generate_receipt import generate_receipt
        from api.jobs.send_notifications import send_receipt_mail
        content = generate_receipt(amount_paid, billingRecord.billingDate, receipt_number, invoice_number, accountId, billepoch, payment_method, billingRecord.supportTier)
        send_receipt_mail(account.pocName, amount_paid, True, billingRecord.paymentPeriod, account.billingEmailAddress, content, account.accountName, invoice_date)
        message = "Payment status updated successfully"
        billingRecord.paymentMade = True
        billingRecord.paymentVerification = portalAdmin.firstName+" "+portalAdmin.lastName
        billingRecord.paymentDate = datetime.now()
        billingRecord.invoiceId = invoice_number
        billingRecord.receiptPDF = base64.b64encode(bytes(content,'Latin-1'))
        #checking for any other pending invoices if account is suspended
        if account.isSuspended:
            account_billing = AccountBilling.query.filter_by(accountId=accountId,paymentMade=False).order_by(AccountBilling.billingDate).first()
            #if all the bills are paid
            if not account_billing:
                account.isSuspended = False
                db.session.add(account)
            #if pending invoice's suspension date is beyond today then unlock the account
            else:
                if account_billing.suspensionDate > datetime.now():
                    account.isSuspended = False
                db.session.add(account)
        safeCommit()
    else:
        message = "Payment status turned to Unpaid"
        billingRecord.paymentMade = False
        billingRecord.paymentDate = None
        billingRecord.paymentVerification = portalAdmin.firstName + " " + portalAdmin.lastName
        account_billing = AccountBilling.query.filter_by(accountId=accountId, paymentMade=False).order_by(AccountBilling.billingDate).first()
        if account_billing.suspensionDate > datetime.now():
            account.isSuspended = False
        else:
            account.isSuspended = True
        db.session.add(account)
    db.session.add(billingRecord)
    safeCommit()
    return {
               "result": {"message": message, "verifiedBy": billingRecord.paymentVerification }
           }, 201

def getDashboardDetails():
    try:
        numberOfAccounts = Account.query.count()
        numberOfUsers = Users.query.count()
        numberOfDevices = Device.query.count()
        return{
            "result":{
                "numberOfAccounts" : numberOfAccounts,
                "numberOfUsers" : numberOfUsers,
                "numberOfDevices": numberOfDevices
            }
        }, 200
    except Exception as e:
        print(str(e))
        abort(400, "Cannot fetch the dashboard details")


def insertRepoDetails(payload, accountId):
    try:
        ha_repo_account = HaRepoAccount.query.filter_by(accountId=accountId).one_or_none()    
        repoAccountId = 0
        print(ha_repo_account)
        if ha_repo_account:
            repoAccountId = ha_repo_account.id
        else :
            ha_repo_account = HaRepoAccount()
        ha_repo_account.status = 'ACTIVE'
        ha_repo_account.clusterAdress = payload['clusterAdress']
        ha_repo_account.clusterSecretKey = payload['clusterSecretKey']
        ha_repo_account.accountId = accountId
        db.session.add(ha_repo_account)
        safeCommit()
        
        if repoAccountId == 0:
            ha_repo_account = HaRepoAccount.query.filter_by(accountId=accountId).one_or_none()
            if ha_repo_account:
                repoAccountId = ha_repo_account.id
        
        ha_repo_server = HaRepoServer.query.filter_by(accountId=accountId).one_or_none()
        if not ha_repo_server: 
            ha_repo_server = HaRepoServer()
        ha_repo_server.status = 'ACTIVE'
        ha_repo_server.accountId = accountId
        ha_repo_server.repoAccountId = repoAccountId
        ha_repo_server.repoAddress = payload['repoAddress']
        ha_repo_server.repoPeerId = payload['repoPeerId']
        ha_repo_server.repoConfig = payload['repoConfig']
        db.session.add(ha_repo_server)
        safeCommit()
        return {
                   "result": {"message": "Successfully saved the HaRepo records"}
               }, 201
    except Exception as e:
        print("errror=>"+str(e))
        abort(400, "Failed to create the HaRepo records, Please try again")

def getHarepoAccountRecord(accountId):
    ha_repo_server = HaRepoServer.query.filter_by(accountId=accountId).one_or_none()
    account = HaRepoAccount.query.filter_by(accountId=accountId).one_or_none()
    haRepo = {
        'repoAddress' : '',#'35.175.147.60',
        'repoPeerId': '',#'12D3KooWBf7YGSytkMAZxSA8myNLBvvZNxxQ8k9nQksta6PhYWCW',
        'repoConfig' : '',#'testing',
        'accountId' : '',#'1xA000003',
        'clusterAdress' : '',#'/ip4/35.175.147.60/tcp/9096/p2p/12D3KooWMThuq3nsLoEedqk8CgX3ikD2SRXsSf8fx7Xp8NY6pdnC',
        'clusterSecretKey' : '',#'2699b1782efe2556deb9a18dd3f860514bc795304fbc4c8bc2d12b1a9ec3523c'
    }
    if account :
        haRepo['clusterAdress'] = account.clusterAdress
        haRepo['clusterSecretKey'] = account.clusterSecretKey
    if ha_repo_server:
        haRepo['repoAddress'] = ha_repo_server.repoAddress
        haRepo['repoPeerId'] = ha_repo_server.repoPeerId
        haRepo['repoConfig'] = ha_repo_server.repoConfig
        haRepo['accountId'] =  ha_repo_server.accountId

    print(haRepo)
   
    return {
            "result": haRepo
            }, 200

'''