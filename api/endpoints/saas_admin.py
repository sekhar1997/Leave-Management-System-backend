from flask import request
from flask_restplus import Resource
from ..define import api
#import saftrus_rbac

from ..handlers.saas_admin import *

ns = api.namespace('LMS', description='LeaveManagementsysyem')

@ns.route('/auth/login')
class ManageLoginInfoHandler(Resource):
    @api.expect(SaasLoginRequest, validate=True)
    @api.marshal_with(LoginResponse)
    def post(self):
        """
        LogIn function
        :return:
        """
        response, code = logInUser(request)
        return response, code

@ns.route('/<string:employeeId>/leaves')
class AppliedLeaves(Resource):
    @api.marshal_with(LeaveRequestData)
    def get(self,employeeId):
        """
        Get applied leaves
        """
        response, code = appliedLeaves(employeeId)
        return response, code


@ns.route('/employee/stats/admin')
class LeaveApproval(Resource):
    @api.marshal_with(LeaveRequestData)
    @api.param('email', 'email')
    def get(self):
        """
        Leave to approve by approver
        """
        email = request.args.get('email')
        response, code = leavesToApprove(email)
        return response, code

    @api.param('leaveId', 'leaveId')
    @api.param('status', 'status')
    def put(self):
        """
        Approve or denie
        """
        leaveId = request.args.get('leaveId')
        status = request.args.get('status')
        response, code = approveLeave(leaveId,status)
        return response, code



@ns.route('/employee/holidays')
class ManageHolidaysList(Resource):
    @api.marshal_with(HolidayData)
    #@login_required
    def get(self):
        """
        Get holiday list
        """
        response, code = holidayList()
        return response, code


@ns.route('/admin/holidays')
class AddHoliday(Resource):
    @api.expect(nestedHolidayData, validate=True)
    def post(self):
        """
        Add holiday
        """
        response, code = addHoliday(request.json)
        return response, code


@ns.route('/employee/leaverequest')
class LeaveRequest(Resource):
    @api.expect(nestedLeaveRequestData, validate=True)
    def post(self):
        """
        Raise leave request
        """
        response, code = raiseLeaveRequest(request.json)
        return response, code

@ns.route('/admin/addemployee/')
class AddEmployee(Resource):
    @api.expect(nestedEmployeedata, validate=True)
    def post(self):
        """
        Add Employee
        """
        response, code = addEmployee(request.json)
        return response, code


@ns.route('/employee/leaves/<string:empid>')
class Leaves(Resource):
    def get(self,empid):
        """
        Leaves stats
        """
        response, code = leavesCount(empid)
        return response, code


@ns.route('/employee/upcomingholiday/')
class UpcomingLeave(Resource):
    @api.marshal_with(HolidayData)
    def get(self):
        """
        Upcoming holiday
        """
        response, code = upcomingHoliday()
        return response, code


    









'''

@ns.route('/account')
class ManageAccountInfoHandler(Resource):
    @api.expect(AccountRecordPost, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def post(self):
        """
        Create a new Organization Account
        """

        response, code = createAccountRecords(request.json)
        return response, code

    @api.marshal_with(AccountRecordResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self):
        """
        Get the list of license order details for the selected account
        """
        response, code = getAllAccountRecords()
        return response, code


@ns.route('/account/<string:accountId>')
class ManageSingleAccountInfoHandler(Resource):
    @api.expect(AccountRecordPut, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def put(self, accountId):
        """
        Updates organization account
        """

        response, code = updateSingleAccountRecords(request, accountId)
        return response, code

    @api.marshal_with(AccountRecordResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self, accountId):
        """
        License subscription details for the chosen account
        """

        response, code = getSingleAccountRecords(request, accountId)
        return response, code

    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def delete(self, accountId):
        """
        Deletes organization account
        """

        response, code = deleteSingleAccountRecords(request, accountId)
        return response, code


@ns.route('/account/<string:accountId>/admin')
class ManageAccountAdminInfoHandler(Resource):
    @api.expect(AccountAdministratorRecordPost, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def post(self, accountId):
        """
        Called when the Administrator needs to create a new Organization Account, which will be used to the application
        """

        response, code = createAccountAdminRecords(request.json, accountId)
        return response, code

    @api.marshal_with(AccountAdministratorRecordResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self, accountId):
        """
        Retrieves a list of all of enterprise administrators associated with organization adminitrator account
        """

        response, code = getAllAccountAdminRecords(request, accountId)
        return response, code


@ns.route('/account/<string:accountId>/admin/<string:adminId>/otp')
class ManageOTP(Resource):
    @api.marshal_with(OTPResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self, accountId, adminId):

        response, code = getOTP(accountId, adminId)
        return response, code

    @api.expect(OTPPost, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def post(self, accountId, adminId):
        response, code = regenerateOTP(accountId, adminId, request)
        return response, code


@ns.route('/account/<string:accountId>/admin/<string:adminId>')
class ManageSingleAccountAdminInfoHandler(Resource):
    @api.expect(AccountAdministratorRecordPut, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def put(self, accountId, adminId):
        """
        Modify the administrator information under the selected orgranization account
        """

        response, code = updateSingleAccountAdminRecords(request, accountId, adminId)
        return response, code

    @api.marshal_with(AccountAdministratorRecordResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self, accountId, adminId):
        """
        Returns the administrator information under the selected orgranization account
        """

        response, code = getSingleAccountAdminRecords(request, accountId, adminId)
        return response, code

    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def delete(self, accountId, adminId):
        """
        Deletes admin.
        """

        response, code = deleteSingleAccountAdminRecords(request, accountId, adminId)
        return response, code


@ns.route('/account/<string:accountId>/admin/<string:adminId>/reset')
class ResetSingleAccountAdminInfoHandler(Resource):
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def post(self, accountId, adminId):
        """
        Change the password
        """

        response, code = resetSingleAccountAdminRecords(request, accountId, adminId)
        return response, code


@ns.route('/account/<string:accountId>/billing')
class ManageAccountBillingInfoHandler(Resource):
    @api.marshal_with(AccountBillingRecordResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self, accountId):
        """
        Displays the billing records for the selected organization account
        """

        response, code = getAllAccountBillingRecords(request, accountId)
        return response, code


@ns.route('/account/<string:accountId>/billing/<string:billingId>')
class ManageSingleAccountBillingInfoHandler(Resource):
    @api.expect(AccountBillingRecordPut)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def put(self, accountId, billingId):
        """
        Modify the billing information under the selected orgranization account
        """

        response, code = updateSingleAccountBillingRecords(request, accountId, billingId)
        return response, code


@ns.route('/account/<string:accountid>/usage/<string:month>')
class ManageAccountUsageInfoHandler(Resource):
    @api.marshal_with(AccountUsageRecordResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self, accountid, month):
        """
        Gets information about the usage for the Year and month specified
        """
        response, code = getAccountUsageRecords(accountid, month)
        return response, code


@ns.route('/auth/meta')
class ManageEntryPoint(Resource):
    @api.param('emailId', 'emailId')
    @api.marshal_with(CheckEmailResponse)
    def get(self):
        """
        LogIn function
        :return:
        """
        response, code = check_email(request)
        return response, code


@ns.route('/auth/login')
class ManageLoginInfoHandler(Resource):
    @api.expect(SaasLoginRequest, validate=True)
    @api.marshal_with(LoginResponse)
    def post(self):
        """
        LogIn function
        :return:
        """
        response, code = logInUser(request)
        return response, code


@ns.route('/auth/logout')
class ManageLogoutInfoHandler(Resource):
    def post(self):
        """
        LogOut function
        :return:
        """
        old_token = guardSaaSAdmin.read_token_from_header()
        response, code = logOutUser(request,old_token)
        return response, code


@ns.route('/auth/update')
class ManageUpdateInfoHandler(Resource):
    @api.expect(SaaSAccountUpdateRequest, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def post(self):
        """
        Update function
        :return:
        """
        jwt_data = saftrus_rbac.get_jwt_data_from_app_context()
        response, code = SaaSPasswordUpdate(request, jwt_data.get('ext',{}).get('portalAdminId'))
        return response, code


@ns.route('/auth/refresh')
class ManageTokenRefreshInfoHandler(Resource):
    #@api.expect(SaaSAccountUpdateRequest)
    @api.marshal_with(SaaSAdminTokenRefreshResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def post(self):
        """
        Update function
        :return:
        """
        old_token = guardSaaSAdmin.read_token_from_header()
        response, code = refreshToken(old_token)
        return response, code


@ns.route('/billingprofile/<string:profileid>/billing-tier/')
class ManageBillingTierInfoHandler(Resource):
    @api.marshal_with(BillingTiersResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self, profileid):
        """
        lists all the BillingTier Records

        """
        response, code = getAllBillingTierRecords(profileid)
        return response, code

    @api.expect(BillingTiersPost, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def post(self, profileid):
        """
        Creates a new BillingTier record

        """
        response, code = createBillingTierRecord(request, profileid)
        return response, code

@ns.route('/billingprofile/<string:profileid>/billing-tier/<string:tierid>')
class ManageSingleBillingTierInfoHandler(Resource):
    @api.marshal_with(BillingTiersResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self, profileid, tierid):
        """
        Lists the BillingTier Record of the given tierName
        :param tierName:

        """
        response, code = getBillingTierRecord(profileid, tierid)
        return response, code

    @api.expect(BillingTiersPost, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def put(self, profileid, tierid):
        """
        Modifies the given BillingTIer record information
        :param tierName:

        """
        response, code = updateBillingTierRecord(request, profileid, tierid)
        return response, code

    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def delete(self, profileid, tierid):
        """
        Deletes the given BillingTier record
        :param tierName:

        """
        response, code = deleteBillingTierRecord(profileid, tierid)
        return response, code


@ns.route('/portaladmin')
class ManagePortalAdministartorsInfoHandler(Resource):
    @api.marshal_with(PortalAdminResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self):
        """
        Lists all the portal administrators
        :return:
        """
        response, code = getAllPortalAdmins()
        return response, code

    @api.expect(PortalAdminPost, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def post(self):
        """

        :return:
        """
        response, code = createPortalAdmin(request)
        return response, code


@ns.route('/portaladmin/<string:portalAdminId>')
class ManageSinglePortalAdministratorInfoHandler(Resource):
    @api.marshal_with(PortalAdminResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self, portalAdminId):
        """
        Lists the information of the provided portalAdminId
        :param portalAdminId:
        :return:
        """
        response, code = getPortalAdmin(portalAdminId)
        return response, code

    @api.expect(PortalAdminPut, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def put(self, portalAdminId):
        """
        Modifies the information of the provided portalAdminId
        :param portalAdminId:
        :return:
        """
        response, code = updatePortalAdmin(request, portalAdminId)
        return response, code

    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def delete(self, portalAdminId):
        """
        deletes the provided PortalAdmin record
        :return:
        """
        response, code = deletePortalAdmin(portalAdminId)
        return response, code


@ns.route('/register')
class ManageRegistrationGenerateOTPHandler(Resource):
    @api.param('adminId', 'adminId')
    def get(self):
        """
        Get OTP

        """
        response, code = generateOTP(request)
        return response, code

    @api.expect(RegistrationRequest, validate=True)
    def post(self):
        """
        Register

        """
        response, code = handleRegistration(request.json)
        return response, code


@ns.route('/register/verify')
class ManageRegistrationVerifyRegistrationHandler(Resource):
    @api.expect(RegistrationVerifyRequest, validate=True)
    def post(self):
        """
        verify otp

        """
        response, code = verifyRegistration(request.json)
        return response, code


@ns.route('/register/totp/image')
class ManageRegistrationImageOTPHandler(Resource):
    @api.expect(RegistrationQRImageRequest, validate=True)
    def post(self):
        """
        verify otp

        """
        response = generateQRImage(request.json)
        return response


@ns.route('/currentaccount')
class ManageCurrentAccountInfo(Resource):
    @api.marshal_with(CurrentSaasAdminInfoResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self):
        """
        Request to get the current admin account information
        :return:
        """
        response, code = getCurrentSaasAdminInfo()
        return response, code


@ns.route('/billingprofile')
class ManageBillingProfilesInfo(Resource):
    @api.marshal_with(BillingProfileResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self):
        """
        Lists all the billing profiles available
        :return:
        """
        response, code = getAllBillingProfiles()
        return response, code

    @api.expect(BillingProfilePost, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def post(self):
        """
        creates a new billing profile
        :return:
        """
        response, code = createBillingProfileRecord(request)
        return response, code


@ns.route('/billingprofile/<string:profileid>')
class ManageSingleBillingProfileInfo(Resource):
    @api.marshal_with(BillingProfileResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self, profileid):
        """
        gets the single billing profile record
        :param profileid:
        :return:
        """
        response, code = getBillingProfileRecord(profileid)
        return response, code

    @api.expect(BillingProfilePost, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def put(self, profileid):
        """
        modifies the existing billing profile
        :param profileid:
        :return:
        """
        response, code = updateBillingProfile(request, profileid)
        return response, code

    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def delete(self, profileid):
        """
        Deletes an existing billing profile
        :param profile:
        :return:
        """
        response, code = deleteBillingProfile(profileid)
        return response, code


@ns.route('/billing/invoice')
class SendInvoice(Resource):
    @api.expect(InvoicePost)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def post(self):
        """
        Sends invoice report to enterprise admin
        """
        response, code = sendInvoice(request)
        return response, code


@ns.route('/forgot-password')
class ForgotPassword(Resource):
    @api.param('emailId', 'emailId')
    def put(self):
        """
        sends OTP inorder to reset the password
        :return:
        """
        response, code = forgotPassword(request)
        return response, code


@ns.route('/initialdata')
class ManageInitialInfoHandler(Resource):
    @api.expect(SaasInitialLoginRequest, validate=True)
    @api.marshal_with(SaaSInitialLoginResponse)
    def post(self):
        """
        LogIn function
        :return:
        """
        response, code = InitialData(request.json)
        return response, code

@ns.route('/upgrade')
class ManageUpgradesInfoHandler(Resource):
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    @api.expect(UpgradeRequest, validate=True)
    # @api.marshal_with()
    def post(self):
        """
        Creates a new Upgrade available to the enterprises from SaaS Portal
        :return:
        """
        response, code = createUpgrade(request.json)
        return response, code
    @api.marshal_with(UpgradeResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self):
        """
        Lists all upgrade records
        :return:
        """
        response, code = listUpgrades()
        return response, code

@ns.route('/upgrade/<string:upgradeId>')
class ManageSingleUpgradeInofHandler(Resource):
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def put(self, upgradeId):
        """
        Updates upgrade package state from AVAILABLE to DISTRIBUTION
        :return:
        """
        response, code = updateUpgrade(upgradeId)
        return response, code

@ns.route('/upgrade/versions')
class manageUpgradeVersionsInfoHandler(Resource):
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    @api.marshal_with(VersionsResponse)
    def get(self):
        """
        Lists all the versions of the available upgrades
        :return:
        """
        response, code = getVersions()
        return response, code


@ns.route('/billingprofile/modifyprofile/<string:profileid>')
class ManageSingleBillingProfileModifyInfo(Resource):
    @api.expect(BillingProfileModifyRecord)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def put(self, profileid):
        """
        Modifies billing profile's profile ID with the given ID
        :return:
        """
        response, code = modifyBillingProfile(request.json, profileid)
        return response, code


@ns.route('/billingtier/modifytier/<string:tierid>')
class ManageSingleBillingTierModifyInfo(Resource):
    @api.expect(BillingTierModifyRecord)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def put(self, tierid):
        """
        Modifies billing profile's profile ID with the given ID
        :return:
        """
        response, code = modifyBillingTier(request.json, tierid)
        return response, code

@ns.route('/upgrade/packages')
class ManageUpgradePackagesInfoHandler(Resource):
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self):
        """
        Lists existing upgrade packages in S3 which are not included in SaaS Portal
        :return:
        """
        response, code = getUpgradePackages()
        return response, code

@ns.route('/account/<string:accountid>/suspension')
class ManageAccountSuspension(Resource):
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def put(self,accountid):
        """
        Updates the suspension status of the account
        :return:
        """
        response, code = modifySuspensionStatus(accountid)
        return response,code

@ns.route('/account/<string:accountid>/paymentmade/<string:billingid>')
class ManageAccountPayment(Resource):
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def put(self,accountid,billingid):
        """
        Updates the  payment status of the account
        :return:
        """
        jwt_data = saftrus_rbac.get_jwt_data_from_app_context()
        response, code = modifyPaymentStatus(accountid,billingid,jwt_data.get('ext',{}).get('portalAdminId'))
        return response,code

@ns.route('/account/dashboard')
class ManageDashboardInfoHandler(Resource):
    @api.marshal_with(DashboardResponse)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def get(self):
        """
        returns the list of accounts,users,devices
        """
        response, code = getDashboardDetails()
        return response, code


@ns.route('/harepo/<string:accountId>/setup')
class ManageHaRepoInfoHandler(Resource):
    @api.expect(HaRepoInfoRecordPost, validate=True)
    @saftrus_rbac.auth_required('PortalAdministrator')
    @saftrus_rbac.roles_required('saas-admin')
    def post(self, accountId):
        """
        Inserts the records into the Harepo tables
        """

        response, code = insertRepoDetails(request.json, accountId)
        return response, code

    def get(self,accountId):
        """
        returns the record of harepoaccount , hareposerver
        """
        response, code = getHarepoAccountRecord(accountId)
        return response, code
'''