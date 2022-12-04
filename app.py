    #NAPOMENA
# Ovaj kod i ostali kodovi koje sam postavio nisu funkcionalini ili su vrlo mizerno funkcionalni,
# želim da Vam to kažem na vrijeme kako ne bi trošili svoje dragocjeno vrijeme na provjeru istog. :)

# Međutim ovaj kod i komentar je moja želja da Vam pokažem bar "vizuelno" i kako sam ja vidio rješenje ovog zadatka.
# Gledajući materijale  koje ste nam slali za pripremu, meni je poznato da mi je bio potreban jedan python kod koji će
# sve ove stranice koje ste  tražili da se naprave povezati i učiniti funkcionalnim. Naravno sve to uz pomoć Flaska
# koji ce nam datu stranicu prikazati na našem pretrživaču, kako bi podatke koje korisnik unosi negdje sačuvali
# potrebna nam je baza tj. SQLAlchemy koja se spominje u kursu koji smo prelazili.
# I naravno kako bi sve to bilo vizuelno "prikladno" potreban nam je neki HTML kod u koji trebamo ubaciti neki bootstrep
# koji je potrebno pronaći i prilagoditi ga našoj stranici sa parametrima koje ste nam Vi dali.
# (...naravno većinu ovog koda je kopiranu, te sam ja to pokušavao prilagoditi....)

# Međutim sve bi to bilo lijepo da ja iz ne znam još kojeg razloga nisam imao problema sa samim Flaskom, u toku kursa,
# koji mi nije htio pokrenut moj kod pisan u Pycharmu pa nakon mučenja i podešavanja Flaska odmah dolaze nove muke
# a to je da ne mogu pokrenuti bazu podataka, tačnije ne mogu je importovat u svoj kod i na svoju stranicu, pa sam to pokušao
# na drugačiji način, tačnije na puno drugih načina, mimo onog sa kursa ali mi ni to nije uspjelo sto me malo obesharbilo,
# pa onda još i problemi da url-om jer ga Pycharm ne želi importovat jer ne dostaju neke bibliote itd, itd......
# ali to je i ljepota IT svijeta da stalno ispred sebe imas prepreke iz kojih ćeš sigurno puno toga naučiti.
# Ako ovo bude posljedni vid moje komunikacije sa vašim timom želim se zahvaliti na ove dvije sedmice i na ovom danu testiranja,
# iako dan sa 2-3 sata sna u njemu sam puno puta doživio osjećaj kada nakon silne muke i nerviranja shvatić šta ti zapravo
# ta jedna linija koda govori.
    # Veliko hvala na tome i jedan veliki programerski pozdrav za Vaš tim!

from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))





if __name__ == "__main__":
    app.run(debug=True)

