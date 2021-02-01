import sys
import settings
from flask import Flask,request,Response,jsonify,Blueprint
#from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
#from flask_mail import Mail, Message
app = Flask(__name__)
CORS(app)

#from api.define import api,api2
from api.define import api
from api.endpoints.saas_admin import ns as adminns
#from api.endpoints.account_admin import ns as accountadminns
# from api.endpoints.user_app import ns as userns
#from api.endpoints.scim_connect import ns as scimns

#Database Settings
from api.database.models import db
#from api.handlers.account_admin import guardEnterpriseAdmin
#from api.handlers.saas_admin import guardSaaSAdmin
#from api.handlers.user_app import guardUserAdmin
#from api.endpoints.scim_connect import guardSCIM

# Mailer Settings
#from api.common.mailer import mail

# Rate limiters
#from ratelimit import *

#from celery import Celery
'''
def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery
'''


def configure_app(flask_app):
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = settings.SQLALCHEMY_DATABASE_URI
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    #flask_app.config['SECRET_KEY'] = 'TGqmth1mr2r77eg6/E6VtbjzUEONkjsm8rFL95XF'
    # flask_app.config['JWT_ACCESS_LIFESPAN'] = settings.JWT_ACCESS_LIFESPAN
    # flask_app.config['SCIM_JWT_ACCESS_LIFESPAN'] = settings.SCIM_JWT_ACCESS_LIFESPAN
    # # mailer configurations
    # flask_app.config['MAIL_SERVER'] = settings.MAIL_SERVER
    # flask_app.config['MAIL_PORT'] = settings.MAIL_PORT
    # flask_app.config['MAIL_USERNAME'] = settings.MAIL_USERNAME
    # flask_app.config['MAIL_PASSWORD'] = settings.MAIL_PASSWORD
    # flask_app.config['MAIL_USE_TLS'] = settings.MAIL_USE_TLS
    # Celery configurations
    # flask_app.config['CELERY_BROKER_URL'] = settings.CELERY_BROKER_URL
    # flask_app.config['CELERY_RESULT_BACKEND'] = settings.CELERY_RESULT_BACKEND


def initialize_app(flask_app):
    configure_app(flask_app)

    blueprint = Blueprint('api', __name__)
    blueprint2 = Blueprint('api_scim', __name__)
    api.init_app(blueprint)
    #api2.init_app(blueprint2)
    #api.add_namespace(accountadminns)
    api.add_namespace(adminns)
    #api.add_namespace(userns)
    #api2.add_namespace(scimns)

    flask_app.register_blueprint(blueprint, url_prefix='/api/v1')
    flask_app.register_blueprint(blueprint2, url_prefix='/api')
    db.app = flask_app
    #guardEnterpriseAdmin.init_app(flask_app, AccountAdministrator)
    #guardSaaSAdmin.init_app(flask_app, PortalAdministrator)
    #guardSCIM.__init__(flask_app, AccountAdministrator )
    #guardUserAdmin.init_app(flask_app, Users)
    db.init_app(flask_app)

    # Mailer configuration
    #mail.init_app(app)


initialize_app(app)
#celery = make_celery(app)

@app.route('/help', methods=['GET'])
def routes_info():
    """Print all defined routes and their endpoint docstrings

    This also handles flask-router, which uses a centralized scheme
    to deal with routes, instead of defining them as a decorator
    on the target function.
    """
    routes = []
    for rule in app.url_map.iter_rules():
        try:
            if rule.endpoint != 'static':
                if hasattr(app.view_functions[rule.endpoint], 'import_name'):
                    import_name = app.view_functions[rule.endpoint].import_name
                    obj = sys.import_string(import_name)
                    routes.append({rule.rule: "%s\n%s" % (",".join(list(rule.methods)), obj.__doc__)})
                else:
                    routes.append({rule.rule: app.view_functions[rule.endpoint].__doc__})
        except Exception as exc:
            routes.append({rule.rule:
                           "(%s) INVALID ROUTE DEFINITION!!!" % rule.endpoint})
            route_info = "%s => %s" % (rule.rule, rule.endpoint)
            app.logger.error("Invalid route: %s" % route_info, exc_info=True)
            # func_list[rule.rule] = obj.__doc__

    return jsonify(code=200, data=routes)


'''
@app.route('/test/mail', methods=['GET'])
#@ratelimitIP(limit=10, per=60 * 5)
def test_mail():
    """sends a test mail"""
    from api.common.mailer import send_email, MailContext
    context = MailContext(name="Uttam",
                          account_name="AxiomIO",
                          account_url="https://axiomio.cydrive.com",
                          email="uttamk@axiomio.com",
                          otp="1234567890123456")
    send_email(template_file="email/admin-account-registration.html",
               subject="Account Activation Success",
               recipients=["uttamk@axiomio.com","uttam.swamy-intl@cylogic.com"],
               context=context)

    return jsonify({"message":"Test mail sent successfully"}),200
  '''
'''
@app.route('/test/payment', methods=['GET'])
def pay_page():
    return """<html><body>
<style>
/**
 * The CSS shown here will not be introduced in the Quickstart guide, but shows
 * how you can use CSS to style your Element's container.
 */
.StripeElement {
  background-color: white;
  height: 40px;
  padding: 10px 12px;
  border-radius: 4px;
  border: 1px solid transparent;
  box-shadow: 0 1px 3px 0 #e6ebf1;
  -webkit-transition: box-shadow 150ms ease;
  transition: box-shadow 150ms ease;
}

.StripeElement--focus {
  box-shadow: 0 1px 3px 0 #cfd7df;
}

.StripeElement--invalid {
  border-color: #fa755a;
}

.StripeElement--webkit-autofill {
  background-color: #fefde5 !important;
}
</style>
<form action="/charge" method="post" id="payment-form">
  <div class="form-row">
    <label for="card-element">
      Credit or debit card
    </label>
    <div id="card-element">
      <!-- A Stripe Element will be inserted here. -->
    </div>

    <!-- Used to display form errors. -->
    <div id="card-errors" role="alert"></div>
  </div>

  <button>Submit Payment</button>
</form>
<script src="https://js.stripe.com/v3/"></script>
<script>
// Create a Stripe client.
var stripe = Stripe('pk_test_6pRNASCoBOKtIshFeQd4XMUh');

// Create an instance of Elements.
var elements = stripe.elements();

// Custom styling can be passed to options when creating an Element.
// (Note that this demo uses a wider set of styles than the guide below.)
var style = {
  base: {
    color: '#32325d',
    lineHeight: '18px',
    fontFamily: '"Helvetica Neue", Helvetica, sans-serif',
    fontSmoothing: 'antialiased',
    fontSize: '16px',
    '::placeholder': {
      color: '#aab7c4'
    }
  },
  invalid: {
    color: '#fa755a',
    iconColor: '#fa755a'
  }
};

// Create an instance of the card Element.
var card = elements.create('card', {style: style});

// Add an instance of the card Element into the `card-element` <div>.
card.mount('#card-element');

// Handle real-time validation errors from the card Element.
card.addEventListener('change', function(event) {
  var displayError = document.getElementById('card-errors');
  if (event.error) {
    displayError.textContent = event.error.message;
  } else {
    displayError.textContent = '';
  }
});

function stripeTokenHandler(token) {
    alert(token);
    console.log(token);
}

// Handle form submission.
var form = document.getElementById('payment-form');
form.addEventListener('submit', function(event) {
  event.preventDefault();

  stripe.createToken(card).then(function(result) {
    if (result.error) {
      // Inform the user if there was an error.
      var errorElement = document.getElementById('card-errors');
      errorElement.textContent = result.error.message;
    } else {
      // Send the token to your server.
      stripeTokenHandler(result.token);
    }
  });
});


</script>
</body></html>
"""
'''

def main():
    app.run(debug=settings.FLASK_DEBUG,port=5020,host='0.0.0.0')


if __name__ == "__main__":
    main()
