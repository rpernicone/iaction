import os
import pathlib
import openai
import stripe
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, session, abort, redirect
from twilio.twiml.messaging_response import MessagingResponse
from twilio.rest import Client
import requests
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from urllib.parse import quote
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
# from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
# from flask_mysqldb import MySQL

load_dotenv()
# create the extension
db = SQLAlchemy()
# create the app
app = Flask(__name__)
# configure the SQLite database, relative to the app instance folder
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://mwema:%s@localhost/god_in_a_box'% quote('Mwema-1234')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:%s@iaction.cswbf3wcvpbu.us-east-2.rds.amazonaws.com/iaction'% quote('actiondb')
#secret key
app.config['SECRET_KEY'] = "my long secret key veryy"
app.secret_key = "mylongsecretkey"
# initialize the app with the extension
db.init_app(app)

# app.config['MYSQL_HOST'] = 'god-in-a-box.cswbf3wcvpbu.us-east-2.rds.amazonaws.com'
# app.config['MYSQL_USER'] = 'admin'
# app.config['MYSQL_PASSWORD'] = 'Mwema-1234'
# app.config['MYSQL_DB'] = 'god_in_a_box'
# db = MySQL(app)

client = Client()

# stripe keys
stripe_keys = {
    "secret_key": os.environ["STRIPE_SECRET_KEY"],
    "publishable_key": os.environ["STRIPE_PUBLISHABLE_KEY"],
    # "endpoint_secret": "http://127.0.0.1:5000/webhook",
    # "endpoint_secret": "https://7b78-41-80-114-156.ngrok.io/callback",
}

stripe.api_key = stripe_keys["secret_key"]

#model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(200), unique=True, nullable=True)
    email = db.Column(db.String(200), unique=True, nullable=True)
    pin = db.Column(db.String(200), nullable=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, name=None, email=None, phone=None, pin=None, date_added=None):
        self.name = name
        self.email = email
        self.phone = phone
        self.pin = pin
        self.date_added = date_added

    def __repr__(self):
        return f'<User {self.name!r}>'
    
class UserSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(200), nullable=True)
    question = db.Column(db.Text, nullable=True)
    answer = db.Column(db.Text, nullable=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, question=None, answer=None, phone=None, date_added=None):
        self.question = question
        self.answer = answer
        self.phone = phone
        self.date_added = date_added

    def __repr__(self):
        return f'<User {self.name!r}>'
    
    
with app.app_context():
    db.create_all()

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
GOOGLE_CLIENT_ID = "730952487468-jpr0ltkbf8u4kr4bfcb4r4fmo02t9h22.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
# flow = Flow.from_client_secrets_file(
#     client_secrets_file=client_secrets_file,
#     scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
#     redirect_uri="https://b9ed-41-90-70-147.ngrok.io/callback"
# )
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://ec2-18-118-200-128.us-east-2.compute.amazonaws.com:5000/callback"
)

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper

   
# index / welcome page
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)
    return redirect("/dashboard")

@app.route("/register")
def register():
    return render_template("login.html")

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    # return id_info
    
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    
    # if email is for admin redirect to admin dashboard
    if id_info.get("email") == "admin@gmail.com":
        return redirect("/admin-dashboard")
        # return redirect("/whatsapp")
        
    return redirect("/whatsapp")
    # otherwise redirect to whatsapp login
    
  

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/whatsapp", methods=['GET', 'POST'])
def whatsapp():
    if request.method == 'POST':
       if session["email"]:
          default_value = '0'
          whatsapp_number = request.form.get('phone', default_value)
          bot_user = User.query.filter_by(phone=whatsapp_number).first()
          # save the user
          if not bot_user:
            app.logger.info('Save User')
            new_user = User(phone=whatsapp_number, name=session["name"], email=session["email"])
            db.session.add(new_user)
            db.session.commit()
            return redirect("/dashboard")
          else:
              return redirect("/dashboard")
            
    return render_template("whatsapp-login.html")

@app.route("/dashboard")
# @login_is_required
def dashboard():
    return render_template("dashboard.html")

@app.route('/subscriptions')
# @login_is_required
def subscriptions():
    return render_template("subscriptions.html")

# admin side
@app.route("/admin-dashboard")
# @login_is_required
def admin_dashboard():
    return render_template("admin-dashboard.html")

@app.route("/users")
# @login_is_required
def users():
    users = User.query.all()
    return render_template("users.html", users=users)

@app.route("/responses")
# @login_is_required
def responses():
    responses = UserSession.query.all()
    return render_template("responses.html", responses=responses)

@app.route("/config")
def get_publishable_key():
    stripe_config = {"publicKey": stripe_keys["publishable_key"]}
    return jsonify(stripe_config)

@app.route("/create-checkout-session")
def create_checkout_session():
    # domain_url = "http://127.0.0.1:5000/"
    domain_url = "http://ec2-18-118-200-128.us-east-2.compute.amazonaws.com:5000/"
    stripe.api_key = stripe_keys["secret_key"]

    try:
        # Create new Checkout Session for the order
        # Other optional params include:
        # [billing_address_collection] - to display billing address details on the page
        # [customer] - if you have an existing Stripe Customer ID
        # [payment_intent_data] - capture the payment later
        # [customer_email] - prefill the email input in the form
        # For full details see https://stripe.com/docs/api/checkout/sessions/create

        # ?session_id={CHECKOUT_SESSION_ID} means the redirect will have the session ID set as a query param
        checkout_session = stripe.checkout.Session.create(
            # new
            # client_reference_id=current_user.id if current_user.is_authenticated else None,
            success_url=domain_url + "success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=domain_url + "cancelled",
            payment_method_types=["card"],
            mode="payment",
            line_items=[
                {
                    "name": "WhatsApp Chatbot Subscription",
                    "quantity": 1,
                    "currency": "usd",
                    "amount": "2000",
                }
            ]
        )
        
        # get user by email
        # session["checkout_user"] = User.query.filter_by(email=checkout_session["customer_details"]["email"]).first()
        # app.logger.info("Checkout user")
        # app.logger.info(session["checkout_user"])
        return jsonify({"sessionId": checkout_session["id"]})
    except Exception as e:
        return jsonify(error=str(e)), 403


@app.route("/success")
def success():
    app.logger.info("success")
    return render_template("success.html")


@app.route("/cancelled")
def cancelled():
    return render_template("cancelled.html")

@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_keys["endpoint_secret"]
        )

    except ValueError as e:
        # Invalid payload
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return "Invalid signature", 400

    # Handle the checkout.session.completed event
    if event["type"] == "checkout.session.completed":
        print("Payment was successful.")
        app.logger.info("Payment was successful.")
        # TODO: run some custom code here

    return "Success", 200


def respond(message):
    response = MessagingResponse()
    response.message(message)
    return str(response)


@app.route('/message', methods=['POST'])
def reply():
    message = request.form.get('Body').lower()
    if message:
        app.logger.info("First hit")
        openai.api_key = os.getenv('OPENAI_API_KEY')
        # chat
        if message == "hello":
           r = openai.ChatCompletion.create(
           model="gpt-3.5-turbo",
           messages=[
              {"role": "user", "content": message}
            ],
           max_tokens=100,
           )
           app.logger.info(r)
           quote = r["choices"][0]["message"]["content"]
           app.logger.info(quote)
           return respond(quote)
       # completion
        else:
         r = openai.Completion.create(
            model="text-davinci-003",
            prompt=message,
            max_tokens=70,
            temperature=0
         )
        #  quote = r["choices"][0]["text"]
        #  app.logger.info("Secondhit")
        #  return respond(quote)
        # return respond(f'Thank you for your message! A member of our team will be in touch with you soon.')
           # check if the response is 200
         if r["choices"][0]["text"]:   
        # check whatsapp parameters - text, phone, name
        # body of the message from user
            text = request.values.get("Body", None)
            app.logger.info(text)
        #  phone number from whatsapp which is not trimed
            phone_number = request.values.get("From", None)
            app.logger.info(phone_number)
        #  whatsapp profile name
            user_name = request.values.get("ProfileName", None)
            app.logger.info(user_name)
         #  whatsapp number
            whatsapp_number = phone_number.replace("whatsapp:", "")
            app.logger.info(whatsapp_number)
        #  check if user exits
            app.logger.info('Fetch User')
            bot_user = User.query.filter_by(phone=whatsapp_number).first()
            app.logger.info(bot_user)
         # if user does not exist save user
            if not bot_user:
              app.logger.info('Save User')
              new_user = User(phone=whatsapp_number, name=user_name)
              db.session.add(new_user)
              db.session.commit()
        
      
        #  count responses
            response = UserSession.query.filter_by(phone=whatsapp_number).count()
            app.logger.info(response)
        #  check if responses are equal to 15 or more than 15
            if response >= 1:
              app.logger.info('Count reached')
              if text == '1':
                 app.logger.info('Redirect to stripe')
                 return respond("https://0136-41-80-113-21.eu.ngrok.io")
              subscription_message = "Hello, your subscription has ended. Reply with a number to choose subscription.\n"
              subscription_message += "1. Redirect to dashboard."
              return respond(subscription_message)
        # if so send a message for subscription then redirect the user to stripe
        # if not save the response and send the whatsapp response
        #  save response
            reply_message = UserSession(phone=whatsapp_number, answer=r["choices"][0]["text"], question=text)
            db.session.add(reply_message)
            db.session.commit()
            app.logger.info("Send whatsapp message")
         #  send message
            quote = r["choices"][0]["text"]
            return respond(quote)
                   
         else:
          return respond("Sorry the server is down. Kindly try again later")


@app.route('/bot', methods=['POST'])
def bot():
    app.logger.info("GPT")
    incoming_msg = request.values.get('Body', '').lower()
    resp = MessagingResponse()
    msg = resp.message()
    responded = False
    if 'gpt' in incoming_msg:
        # return a quote
        app.logger.info("Test: GPT")
        openai.api_key = os.getenv('OPENAI_API_KEY')
        r = openai.Completion.create(
            model="text-davinci-003",
            prompt=incoming_msg,
            # prompt="What is Laravel?",
            max_tokens=70,
            temperature=0
        )
        app.logger.info(r)
        app.logger.info(r["choices"][0]["text"])
        # data = r.json()
        quote = r["choices"][0]["text"]
        # r = requests.get('https://api.quotable.io/random')
        # if r.status_code == 200:
        #     data = r.json()
        #     quote = f'{data["content"]} ({data["author"]})'
        # else:
        #     quote = 'I could not retrieve a quote at this time, sorry.'
        msg.body(quote)
        responded = True
    if 'cat' in incoming_msg:
        # return a cat pic
        msg.media('https://cataas.com/cat')
        responded = True
    if not responded:
        app.logger.info("Not GPT")
        msg.body('I only know about famous quotes and cats, sorry!')
    return str(resp)
