from flask_restplus import Api
from sqlalchemy.orm.exc import NoResultFound
import settings

# API for enterprise CyDrive Application
api = Api(version='1.0', title='AXIOMIO LMS', description='AXIOMIO leave management system')
#api2 = Api(version='1.0', title='CyDrive SaaS API', description='CyDrive API', authorizations=settings.authorizations)


@api.errorhandler
def default_error_handler(e):
    print(str(e))
    message = 'Internal Server Error, Please try again later'
    return {'message': message}, 500


@api.errorhandler(NoResultFound)
def database_not_found_error_handler(e):
    return {'message': 'Cannot find the record {message}'.format(message=str(e))}, 404
